# D7's install path, on real machines: alice on client runs `mosey HOST`
# through the system ssh, as a user would, against two hosts.
#
# - server has mosey on its PATH (the package from this flake): a whole
#   session runs over real UDP between the VMs, with the server's roles
#   sandboxed as released (seccomp KILL, Landlock), and what alice types
#   in it reaches server's shell.
# - bare has no mosey at all. TODAY (slice 1) the client says so and
#   exits: bootstrap.md §4.2's ErrNoServer, which is the hook the
#   auto-upload slice answers. THE AUTO-UPLOAD SLICE CHANGES THIS CASE: it
#   asks the first time (D7), so its test answers yes and expects a session
#   on bare, run by ~/.cache/mosey/<version>/mosey, hash-checked, and a
#   second run that asks nothing.
#
# Throwaway keys, made in the store for this test alone; nothing here reads
# a real key, agent or known_hosts.
{ self }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  mosey = self.packages.${system}.mosey;

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

    # SLICE 1 BEHAVIOUR, to be replaced by the auto-upload slice (see the
    # header): the client finds no mosey on bare and says how to fix it.
    with subtest("bare: no mosey there, said plainly (until auto-upload)"):
        client.succeed(alice(
            "tmux new-session -d -s b -x 100 -y 30 "
            + shlex.quote("mosey bare 2>/tmp/bare-err; echo $? >/tmp/bare-exit")
        ))
        client.wait_for_file("/tmp/bare-exit")
        status = client.succeed("cat /tmp/bare-exit").strip()
        err = client.succeed("cat /tmp/bare-err")
        assert status != "0", f"mosey bare exited 0: {err}"
        assert "no mosey at mosey on bare" in err, f"stderr: {err}"
  '';
}
