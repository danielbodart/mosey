# D7's install path, on real machines: alice on client runs `mosey HOST`
# through the system ssh, as a user would, against two hosts.
#
# - server has mosey on its PATH (the flake's package, which is a release
#   binary: on a tag the release's own, in CI the one its run built): a whole
#   session runs over real UDP between the VMs, with the server's roles
#   sandboxed as released (seccomp KILL, Landlock), and what alice types
#   in it reaches server's shell.
# - bare has no mosey at all (D7, bootstrap.md §4.7). The client's probe
#   says so, the client asks the first time, alice answers yes, and the
#   client copies its own file to ~/.local/bin/mosey on bare, making
#   ~/.local/bin, where the installer checks its hash; the session then
#   runs from that copy. A second run finds it and asks nothing. Hopping
#   on from that copy (`mosey otherhost` inside the session) is not
#   checked: no stock NixOS profile puts ~/.local/bin on PATH, so NixOS
#   needs mosey from Nix to hop on (Dan, 2026-11-16; bootstrap.md
#   §4.7.9).
#
# Throwaway keys, made in the store for this test alone; nothing here reads
# a real key, agent or known_hosts.
{ mosey }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  # Where D7 installs this build on a host that has none: the one file,
  # whatever its version (bootstrap.md §4.7).
  installed = "/home/alice/.local/bin/mosey";

  keys = pkgs.runCommand "mosey-install-test-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C alice -f $out/alice
    ssh-keygen -q -t ed25519 -N "" -C server -f $out/server
    ssh-keygen -q -t ed25519 -N "" -C bare -f $out/bare
  '';

  alice = {
    isNormalUser = true;
    uid = 1000;
    group = "users";
    openssh.authorizedKeys.keyFiles = [ "${keys}/alice.pub" ];
  };

  host = name: {
    services.openssh = {
      enable = true;
      hostKeys = [{ path = "/etc/ssh/ssh_host_ed25519_key"; type = "ed25519"; }];
      settings.PasswordAuthentication = false;
      settings.KbdInteractiveAuthentication = false;
    };
    environment.etc."ssh/ssh_host_ed25519_key" = { source = "${keys}/${name}"; mode = "0600"; };
    environment.etc."ssh/ssh_host_ed25519_key.pub" = { source = "${keys}/${name}.pub"; mode = "0644"; };
    users.users.alice = alice;
    # The server binds a UDP port in 60000-61000 (bootstrap.md §11), as
    # Mosh's does; a host running mosey opens that range.
    networking.firewall.allowedUDPPortRanges = [{ from = 60000; to = 61000; }];
  };
in
{
  name = "mosey-install";

  nodes.client = { ... }: {
    users.users.alice = alice;
    environment.systemPackages = [ mosey pkgs.tmux ];
    programs.ssh.knownHosts = {
      server.publicKeyFile = "${keys}/server.pub";
      bare.publicKeyFile = "${keys}/bare.pub";
    };
  };

  nodes.server = { ... }: {
    imports = [ (host "server") ];
    environment.systemPackages = [ mosey ];
  };

  nodes.bare = { ... }: {
    imports = [ (host "bare") ];
  };

  testScript = ''
    import shlex

    def alice(cmd):
        return "su - alice -c " + shlex.quote(cmd)

    def pane(name):
        return client.succeed(alice(f"tmux capture-pane -p -t {name}"))

    start_all()
    server.wait_for_unit("sshd.service")
    bare.wait_for_unit("sshd.service")
    client.wait_for_unit("multi-user.target")
    # alice's key, where ssh looks for it.
    client.succeed("install -d -o alice -g users -m 0700 /home/alice/.ssh")
    client.succeed("install -o alice -g users -m 0600 ${keys}/alice /home/alice/.ssh/id_ed25519")

    with subtest("bare has no mosey"):
        bare.fail("command -v mosey")

    with subtest("a session on server: typing reaches its shell, exit ends it"):
        client.succeed(alice(
            "tmux new-session -d -s s -x 100 -y 30 "
            + shlex.quote("mosey server 2>/tmp/server-err; echo $? >/tmp/server-exit")
        ))
        # NixOS's prompt names the user and host: the remote shell is up,
        # drawn through mosey's diffs.
        client.wait_until_succeeds(alice("tmux capture-pane -p -t s | grep -q 'alice@server'"), timeout=60)
        server.succeed("pgrep -u alice -f -- '--serve=spawner'")
        client.succeed(alice("tmux send-keys -t s 'touch /tmp/through-mosey' Enter"))
        server.wait_for_file("/tmp/through-mosey")
        server.succeed("test \"$(stat -c %U /tmp/through-mosey)\" = alice")
        client.succeed(alice("tmux send-keys -t s exit Enter"))
        client.wait_for_file("/tmp/server-exit")
        status = client.succeed("cat /tmp/server-exit").strip()
        assert status == "0", f"mosey server exited {status}: {client.succeed('cat /tmp/server-err')}"
        # The session's processes end with it.
        server.wait_until_fails("pgrep -u alice -f -- '--serve'")

    with subtest("bare: asked once, mosey copies itself there and the session runs from the copy"):
        client.succeed(alice(
            "tmux new-session -d -s b -x 100 -y 30 "
            + shlex.quote("mosey bare 2>/tmp/bare-err; echo $? >/tmp/bare-exit")
        ))
        # The question goes to stderr while the terminal is cooked; the
        # answer comes from the terminal (bootstrap.md §4.7.5).
        client.wait_until_succeeds("grep -q 'Copy this one' /tmp/bare-err", timeout=60)
        client.succeed(alice("tmux send-keys -t b y Enter"))
        client.wait_until_succeeds(alice("tmux capture-pane -p -t b | grep -q 'alice@bare'"), timeout=60)
        # The very file the client runs, owned by alice and hers alone.
        want = client.succeed("sha256sum ${mosey}/bin/mosey").split()[0]
        got = bare.succeed("sha256sum ${installed}").split()[0]
        assert got == want, f"the copy on bare is {got}, the client is {want}"
        bare.succeed("test \"$(stat -c '%U %a' ${installed})\" = 'alice 700'")
        # The upload made ~/.local and ~/.local/bin, hers alone.
        bare.succeed("test \"$(stat -c '%U %a' /home/alice/.local /home/alice/.local/bin | sort -u)\" = 'alice 700'")
        # The spawner runs from the copy (a pattern without the version,
        # whose + pgrep would read as a regular expression).
        bare.succeed("pgrep -u alice -f -- '/home/alice/[.]local/bin/mosey --serve=spawner'")
        client.succeed(alice("tmux send-keys -t b 'touch /tmp/through-the-copy' Enter"))
        bare.wait_for_file("/tmp/through-the-copy")
        client.succeed(alice("tmux send-keys -t b exit Enter"))
        client.wait_for_file("/tmp/bare-exit")
        status = client.succeed("cat /tmp/bare-exit").strip()
        assert status == "0", f"mosey bare exited {status}: {client.succeed('cat /tmp/bare-err')}"
        bare.wait_until_fails("pgrep -u alice -f -- '--serve'")

    with subtest("bare again: the copy is found, nothing is asked"):
        client.succeed(alice(
            "tmux new-session -d -s b2 -x 100 -y 30 "
            + shlex.quote("mosey bare 2>/tmp/bare2-err; echo $? >/tmp/bare2-exit")
        ))
        client.wait_until_succeeds(alice("tmux capture-pane -p -t b2 | grep -q 'alice@bare'"), timeout=60)
        client.fail("grep -q 'y/N' /tmp/bare2-err")
        client.succeed(alice("tmux send-keys -t b2 exit Enter"))
        client.wait_for_file("/tmp/bare2-exit")
        status = client.succeed("cat /tmp/bare2-exit").strip()
        assert status == "0", f"mosey bare exited {status}: {client.succeed('cat /tmp/bare2-err')}"
  '';
}
