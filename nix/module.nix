# programs.mosey: mosey on a NixOS machine. Turning it on puts mosey on
# PATH and opens the server's UDP ports, as programs.mosh does for mosh,
# and nothing else; every desktop integration is a separate option, off
# by default.
#
# Why a system module and not only a package: the server listens on UDP
# 60000-61000 (server.md §2.2), which a home-manager package cannot open.
# And a Nix-installed mosey is what lets a session hop on to another host
# (`mosey otherhost` inside it): no stock NixOS profile puts ~/.local/bin,
# where D7 installs mosey, on PATH (bootstrap.md §4.7.9).
#
# The flake passes itself in, for the default package: the release this
# flake is (nix/release.json). On trunk there is none, so the package
# must be given.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.programs.mosey;
  provider = cfg.gnome.searchProvider;
  system = pkgs.stdenv.hostPlatform.system;
in
{
  options.programs.mosey = {
    enable = lib.mkEnableOption "mosey, a remote terminal for bad networks";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${system}.default or (throw
        "programs.mosey.package: this mosey flake has no package for ${system}; pin a release tag (github:danielbodart/mosey/vX.Y.Z), or set the package");
      defaultText = lib.literalExpression "inputs.mosey.packages.\${system}.default";
      description = "The mosey package: by default the release this flake is.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to open UDP 60000-61000, the ports the mosey server
        listens on: the range mosh uses, so a firewall opened for mosh lets
        mosey through too.
      '';
    };

    gnome.searchProvider = {
      enable = lib.mkEnableOption ''
        the GNOME Shell search provider: detached sessions, and sessions on
        this machine attached from another, appear in Overview search
        (type mosey, a session name, a program or a directory), and Enter
        opens one in a terminal. Locally attached sessions never appear,
        so search cannot take one from the window it is in. The service is
        started by D-Bus when GNOME Shell searches and exits when idle. Log
        out and in again for GNOME Shell to load it'';

      terminal = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "kgx --close-on-exit";
        description = ''
          The command a result opens in, given `-- mosey -s NAME
          -close-if-idle` after it. Null is the provider's own choice: kgx
          (GNOME Console), else gnome-terminal, else ptyxis. Note that
          Console leaves a window it was given a command for open, read
          only, when that command exits.
        '';
      };

      desktopId = lib.mkOption {
        type = lib.types.str;
        default = "mosey.desktop";
        example = "org.gnome.Console.desktop";
        description = ''
          The app the results are listed under in Overview search. The
          default is mosey's own launcher, which is installed with the
          provider and opens a new session. Name another app (a terminal
          that always runs mosey, say) and mosey.desktop is not installed.
          GNOME Shell silently ignores a provider whose app is hidden
          (NoDisplay=true) or not installed.
        '';
      };

      package = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        default = pkgs.callPackage ./gnome-search-provider.nix {
          mosey = cfg.package;
          inherit (provider) terminal desktopId;
        };
        defaultText = lib.literalMD "built from the options above";
        description = "The search provider as installed.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      environment.systemPackages = [ cfg.package ];
      networking.firewall.allowedUDPPortRanges = lib.optional cfg.openFirewall {
        from = 60000;
        to = 61000;
      };
    })

    (lib.mkIf provider.enable {
      assertions = [{
        assertion = cfg.enable;
        message = "programs.mosey.gnome.searchProvider needs programs.mosey.enable";
      }];
      # GNOME Shell finds the .ini and the icons through
      # /run/current-system/sw/share, and D-Bus the service file through
      # services.dbus.packages.
      environment.systemPackages = [ provider.package ];
      services.dbus.packages = [ provider.package ];
    })
  ];
}
