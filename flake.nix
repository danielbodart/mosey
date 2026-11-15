{
  description = "A remote terminal for bad networks: roams, survives lossy links, picks up where it left off";

  # nixos-26.05, the release nix-config builds every host from, as quoin's,
  # frisket's and chase's flakes take it, so what this flake builds and
  # pushes to the cache is the derivation a host builds.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
      # mosey builds for darwin too (D10, D22: nothing may rule macOS out),
      # so the package and the shell are there for a Mac; the checks, which
      # run VMs and the server's Linux-only sandbox, are Linux's. Not
      # x86_64-darwin: nixpkgs 26.05 is the last release to support it (it
      # warns so on evaluation), and an Intel Mac has the darwin-amd64
      # release binary, which scripts/build.sh makes without Nix. CI builds
      # x86_64-linux and evaluates every other system here
      # (scripts/nix-eval-systems.sh).
      systems = linuxSystems ++ [ "aarch64-darwin" ];
      forAllSystems = lib.genAttrs systems;
      forLinux = lib.genAttrs linuxSystems;

      # A build from a commit rather than a release: MAJOR-unstable-DATE+REV.
      # A release is a tag named by scripts/version.sh, which needs the
      # repository to count, and a build from a store path has none. The
      # commit is in it, unlike the siblings' 0-unstable-DATE, because the
      # server a client installs is kept under its version (D7, bootstrap.md
      # §4.7): two builds of different commits must never claim to be the
      # same mosey. It fits swver's grammar (bootstrap.md §6.1).
      version =
        let
          d = self.lastModifiedDate or "19700101";
          rev = self.shortRev or self.dirtyShortRev or "dirty";
        in
        "${lib.fileContents ./VERSION}-unstable-${builtins.substring 0 4 d}-${builtins.substring 4 2 d}-${builtins.substring 6 2 d}+${rev}";

      # Go's major.minor, the one mise.toml pins: both channels compile with
      # the same language version.
      go = pkgs: pkgs.go_1_27;

      # The Go module alone, so a change to the docs, the workflows or the VM
      # tests does not rebuild the binary.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [ ./cmd ./internal ./go.mod ./go.sum ];
      };

      # The package compiles and nothing else: the tests and the lint are
      # mise run check's (CI's check job), which runs them where the
      # end-to-end tests have an sshd and a tty, so the VM test and a host's
      # system wait only for the compile.
      mkMosey = pkgs: (pkgs.buildGoModule.override { go = go pkgs; }) {
        pname = "mosey";
        inherit version src;

        # Pinned rather than null, because there are dependencies
        # (DEPENDENCIES.md says why each is there). scripts/vendor-hash.sh
        # works it out again whenever the vendored set moves: when go.sum
        # does, and when code first imports another package of a module it
        # already requires. mise run check's vendor-hash-check catches both.
        vendorHash = "sha256-rCMdmdTtz5Gm9LnvHaF9SsojytfIvKaqvvK3FKWyEwQ=";

        subPackages = [ "cmd/mosey" ];

        # A STATIC BINARY (D1), as the releases are: the copy D7 sends over
        # must run on any Linux, whatever its libc.
        env.CGO_ENABLED = 0;
        # As scripts/build.sh builds linux releases (D20): the handshake and
        # rekeys run under runtime/secret. The experiment is linux-only.
        env.GOEXPERIMENT = lib.optionalString pkgs.stdenv.hostPlatform.isLinux "runtimesecret";

        ldflags = [ "-s" "-w" "-X" "main.version=${version}" ];

        # buildGoModule would run `go test` here; the tests are mise run
        # check's (see above).
        doCheck = false;

        meta = {
          description = "A remote terminal for bad networks: roams, survives lossy links, picks up where it left off";
          homepage = "https://github.com/danielbodart/mosey";
          license = lib.licenses.asl20;
          mainProgram = "mosey";
          platforms = lib.platforms.linux ++ lib.platforms.darwin;
        };
      };
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        rec {
          mosey = mkMosey pkgs;
          default = mosey;
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            # openssh for the end-to-end tests, which skip without an sshd;
            # shellcheck and actionlint for mise run check. mkShell's stdenv
            # brings a C compiler, so `CGO_ENABLED=1 go test -race ./...`
            # (mise run race) works here.
            packages = [ (go pkgs) pkgs.gopls pkgs.openssh pkgs.shellcheck pkgs.actionlint ];
            # The same setting the package builds with, so a `go build` in the
            # shell produces the same binary the flake does rather than a
            # dynamically linked one that works here and nowhere else.
            CGO_ENABLED = "0";
          };
        });

      checks = forLinux (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          # Only what needs Nix to check: that the package builds, from the
          # vendored modules with nixpkgs' Go, and the VM test. The tests,
          # gofmt and vet for every platform are mise run check's (CI's
          # check job, which a release needs), and building them here as
          # well only ran them twice. The race detector is CI's race job,
          # and the seccomp KILL soak its kill-soak job: both need what a
          # build sandbox does not give (a C compiler for one, a user's
          # systemd scope with a CPU quota for the other).

          # The build.
          inherit (self.packages.${system}) mosey;

          # D7's install path on real machines: a client VM runs mosey
          # against one server that has it and one that does not, which it
          # copies itself to (tests/install.nix).
          vm-install = pkgs.testers.runNixOSTest (import ./tests/install.nix { inherit self; });
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
