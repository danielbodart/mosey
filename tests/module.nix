# programs.mosey (nix/module.nix), evaluated without a VM: what each
# setting puts on the machine, and that the search provider builds and is
# wired to the mosey it was given. A stand-in mosey, a script that prints
# nothing, so this runs on trunk, where the flake has no package.
{ self, nixpkgs, system }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;
  mosey = pkgs.writeShellScriptBin "mosey" "" // { version = "0.0.0-test"; };
  machine = settings: (lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      # A second import, as a configuration importing it from two
      # features would: the module's key makes it one.
      self.nixosModules.mosey
      { system.stateVersion = "26.05"; }
      { programs.mosey = { package = mosey; } // settings; }
    ];
  }).config;

  off = machine { };
  on = machine { enable = true; };
  closed = machine { enable = true; openFirewall = false; };
  search = machine { enable = true; gnome.searchProvider.enable = true; };
  console = machine {
    enable = true;
    gnome.searchProvider = {
      enable = true;
      terminal = "kgx --close-on-exit";
      desktopId = "org.gnome.Console.desktop";
    };
  };
  orphan = machine { gnome.searchProvider.enable = true; };

  udp = c: c.networking.firewall.allowedUDPPortRanges;
  has = c: p: builtins.elem p c.environment.systemPackages;
  # Only the module's own: a bare machine fails the rest (no root file
  # system, no boot loader).
  failed = c: builtins.filter (a: !a.assertion && lib.hasPrefix "programs.mosey" a.message) c.assertions;
  check = cond: what: cond || throw "tests/module.nix: ${what}";
in
assert check (!(has off mosey) && udp off == [ ]) "off, it installs nothing and opens nothing";
assert check (has on mosey && udp on == [{ from = 60000; to = 61000; }]) "on, it installs mosey and opens 60000-61000";
assert check (has closed mosey && udp closed == [ ]) "openFirewall = false opens nothing";
assert check (!(has on on.programs.mosey.gnome.searchProvider.package)) "the search provider is off by default";
assert check (failed orphan != [ ]) "the search provider alone is refused";
assert check (failed search == [ ] && failed console == [ ]) "the search provider with mosey is accepted";
pkgs.runCommand "mosey-module-check"
{
  default = search.programs.mosey.gnome.searchProvider.package;
  console = console.programs.mosey.gnome.searchProvider.package;
  mosey = lib.getExe mosey;
}
  ''
    fail() { echo "tests/module.nix: $*" >&2; exit 1; }
    ini=share/gnome-shell/search-providers/mosey-search-provider.ini
    svc=share/dbus-1/services/org.mosey.SearchProvider.service

    grep -qx "DesktopId=mosey.desktop" "$default/$ini" || fail "default DesktopId"
    grep -qx "Exec=$default/bin/mosey-search-provider" "$default/$svc" || fail "D-Bus Exec"
    grep -q "^Exec=kgx -- $mosey -new -close-if-idle$" "$default/share/applications/mosey.desktop" \
      || fail "mosey.desktop runs this mosey in kgx"
    grep -q "MOSEY_BIN.*$mosey" "$default/bin/mosey-search-provider" || fail "MOSEY_BIN"
    ! grep -q MOSEY_TERMINAL "$default/bin/mosey-search-provider" || fail "no terminal set, yet MOSEY_TERMINAL"
    test -f "$default/share/icons/hicolor/256x256/apps/mosey.png" || fail "icons"

    grep -qx "DesktopId=org.gnome.Console.desktop" "$console/$ini" || fail "desktopId"
    test ! -e "$console/share/applications/mosey.desktop" || fail "mosey.desktop beside another app"
    grep -q "MOSEY_TERMINAL.*kgx --close-on-exit" "$console/bin/mosey-search-provider" || fail "terminal"
    touch $out
  ''
