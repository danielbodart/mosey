# GNOME Shell search provider for mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

This search provider shows your local `mosey` sessions in GNOME Shell
Overview search. Press `Super`, type `mosey`, a session name, a program
name (such as `claude`), or a directory, and press `Enter` to open the
session in a terminal.

## Which sessions appear

- **Zero network:** the provider queries only sessions on this computer.
- **Locally attached sessions are hidden:** a session that is open in a
  local terminal never appears, so search cannot steal it from another
  window.
- **Detached sessions** appear as `Detached · <name>`.
- **Remotely attached sessions** (hosted on this computer, attached from
  another computer) appear as `Remote (<ip>) · <name>`, so you can bring
  them back onto this desktop.

The service starts on demand through D-Bus and exits after 30 seconds
with no search calls.

## Terminal selection

By default, the provider opens sessions with:

```sh
kgx -- mosey -s <name> -close-if-idle
```

If `kgx` is not installed, it falls back to `gnome-terminal` and then
`ptyxis`. Set `MOSEY_TERMINAL` in the D-Bus session environment to use a
different terminal command (for example, `MOSEY_TERMINAL="ptyxis --new-window"`).

## Manual install

Requirements: `mosey`, `python3`, and PyGObject (`python3-gi` /
`pygobject3`).

```sh
install -Dm0755 gnome-search-provider/mosey-search-provider \
  ~/.local/bin/mosey-search-provider
install -Dm0644 gnome-search-provider/mosey.desktop \
  ~/.local/share/applications/mosey.desktop
install -Dm0644 gnome-search-provider/mosey-search-provider.ini \
  ~/.local/share/gnome-shell/search-providers/mosey-search-provider.ini
install -Dm0644 logo.png \
  ~/.local/share/icons/hicolor/512x512/apps/mosey.png
sed "s|^Exec=.*|Exec=$HOME/.local/bin/mosey-search-provider|" \
  gnome-search-provider/org.mosey.SearchProvider.service \
  > ~/.local/share/dbus-1/services/org.mosey.SearchProvider.service
```

Log out and log in again so GNOME Shell loads the new search provider.

## NixOS

Install the files into a package derivation with a Python environment
that includes `pygobject3` and `glib` (for `Gio` and `GLib` typelibs),
replace `Exec=` in `org.mosey.SearchProvider.service` with
`$out/bin/mosey-search-provider`, and add the package to
`environment.systemPackages`:

```nix
pkgs.stdenvNoCC.mkDerivation {
  pname = "mosey-gnome-search-provider";
  version = "0.1.0";
  src = ./.; # mosey repo root
  nativeBuildInputs = [ pkgs.wrapGAppsNoGuiHook ];
  buildInputs = [
    (pkgs.python3.withPackages (ps: [ ps.pygobject3 ]))
    pkgs.glib
  ];
  installPhase = ''
    runHook preInstall
    install -Dm0755 gnome-search-provider/mosey-search-provider $out/bin/mosey-search-provider
    install -Dm0644 gnome-search-provider/mosey.desktop $out/share/applications/mosey.desktop
    install -Dm0644 gnome-search-provider/mosey-search-provider.ini \
      $out/share/gnome-shell/search-providers/mosey-search-provider.ini
    install -Dm0644 logo.png $out/share/icons/hicolor/512x512/apps/mosey.png
    install -Dm0644 gnome-search-provider/org.mosey.SearchProvider.service \
      $out/share/dbus-1/services/org.mosey.SearchProvider.service
    substituteInPlace $out/share/dbus-1/services/org.mosey.SearchProvider.service \
      --replace-fail "Exec=/usr/bin/env mosey-search-provider" "Exec=$out/bin/mosey-search-provider"
    runHook postInstall
  '';
}
```

## Tests

Run the unit tests with standard Python (no live GNOME Shell needed):

```sh
python3 -m unittest discover -s gnome-search-provider -v
```
