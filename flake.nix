{
  description = "A remote terminal for bad networks: roams, survives lossy links, picks up where it left off";

  # nixos-26.05, the release nix-config builds every host from, as quoin's,
  # frisket's and chase's flakes take it. The package needs little from it
  # (a derivation that installs one file); the dev shell and the VM test
  # need the rest.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
      # The dev shell's systems. mosey builds for darwin too (D10, D22:
      # nothing may rule macOS out), so there is a shell for a Mac; the
      # checks, which run VMs and the server's Linux-only sandbox, are
      # Linux's. Not x86_64-darwin: nixpkgs 26.05 is the last release to
      # support it (it warns so on evaluation), and an Intel Mac building
      # mosey has mise. CI evaluates every system it does not build on
      # (scripts/nix-eval-systems.sh).
      systems = linuxSystems ++ [ "aarch64-darwin" ];
      forAllSystems = lib.genAttrs systems;
      forLinux = lib.genAttrs linuxSystems;

      # THE PACKAGE IS THE RELEASE BINARY, not a build from source (Dan,
      # 2026-11-15): the binaries are built once, by mise's Go in CI's build
      # job, tested, attested and published (bootstrap.md §4.6), and
      # building them again here only made a second binary that was not the
      # one released. So a release's tag is a commit of its own, a child of
      # the released trunk commit, that adds nix/release.json: the version,
      # and for each system the asset's URL and hash (scripts/release-json.sh
      # writes it; ci.yml's release job commits and tags it). A flake fetched
      # as github:danielbodart/mosey/v<V> cannot see its tag, only its
      # commit, which is why the version is in the file.
      #
      # On trunk there is no such file and no package: pin a release tag.
      # Absent rather than an error, so `nix flake check` and the dev shell
      # still work on trunk.
      releaseFile = ./nix/release.json;
      release =
        if builtins.pathExists releaseFile
        then lib.importJSON releaseFile
        else null;

      # One static binary (D1) installed as bin/mosey, byte for byte the
      # file `binary` names: no stripping or patching, which a static Go
      # binary needs on neither NixOS nor darwin, and which would make it
      # differ from the release's SHA256SUMS and from what D7 copies to a
      # host.
      mkMosey = pkgs: { version, binary }: pkgs.stdenvNoCC.mkDerivation {
        pname = "mosey";
        inherit version;
        src = binary;
        dontUnpack = true;
        dontConfigure = true;
        dontBuild = true;
        installPhase = ''
          runHook preInstall
          install -Dm0755 $src $out/bin/mosey
          runHook postInstall
        '';
        dontFixup = true;
        meta = {
          description = "A remote terminal for bad networks: roams, survives lossy links, picks up where it left off";
          homepage = "https://github.com/danielbodart/mosey";
          license = lib.licenses.asl20;
          mainProgram = "mosey";
          # The four the release ships (D10), as release.json lists them.
          platforms = if release == null then [ ] else builtins.attrNames release.assets;
          sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
        };
      };

      # The release's package for each system it has an asset for.
      releasePackages =
        lib.mapAttrs
          (system: asset:
            let
              pkgs = nixpkgs.legacyPackages.${system};
              mosey = mkMosey pkgs {
                inherit (release) version;
                binary = pkgs.fetchurl { inherit (asset) url hash; };
              };
            in
            { inherit mosey; default = mosey; })
          release.assets;
    in
    {
      packages = if release == null then { } else releasePackages;

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            # Go, as mise.toml pins its major.minor, for a shell without
            # mise; openssh for the end-to-end tests, which skip without an
            # sshd; shellcheck and actionlint for mise run check. mkShell's
            # stdenv brings a C compiler, so `CGO_ENABLED=1 go test -race
            # ./...` (mise run race) works here.
            packages = [ pkgs.go_1_27 pkgs.gopls pkgs.openssh pkgs.shellcheck pkgs.actionlint ];
            # Static, as the releases are (D1), rather than a dynamically
            # linked binary that works here and nowhere else.
            CGO_ENABLED = "0";
          };
        });

      # Only what needs Nix to check: D7's install path on real machines, a
      # client VM running mosey against one server that has it and one that
      # does not, which it copies itself to (tests/install.nix). It tests
      # the release package, so it exists where nix/release.json does: on a
      # release tag, and in CI's nix job, which writes one for the binaries
      # its own run built. The tests, gofmt and vet are mise run check's.
      checks = forLinux (system:
        lib.optionalAttrs (self.packages ? ${system}) {
          vm-install = nixpkgs.legacyPackages.${system}.testers.runNixOSTest
            (import ./tests/install.nix { mosey = self.packages.${system}.mosey; });
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
