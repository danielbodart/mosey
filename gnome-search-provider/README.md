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

`mosey.desktop` also puts a `mosey` launcher in the app grid. It opens a
new session (`kgx -- mosey -new -close-if-idle`). Do not hide it with
`NoDisplay=true`: GNOME Shell ignores a search provider whose desktop
file is hidden, and it does not log the reason. To show the sessions
under a different app (for example, a terminal that always runs
`mosey`), change `DesktopId` in `mosey-search-provider.ini` to that
app's desktop file.

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
mkdir -p ~/.local/share/icons
cp -r gnome-search-provider/icons/hicolor ~/.local/share/icons/
sed "s|^Exec=.*|Exec=$HOME/.local/bin/mosey-search-provider|" \
  gnome-search-provider/org.mosey.SearchProvider.service \
  > ~/.local/share/dbus-1/services/org.mosey.SearchProvider.service
```

Log out and log in again so GNOME Shell loads the new search provider.

## NixOS

mosey's flake has a NixOS module. Import it, turn on mosey, and turn on
the search provider:

```nix
{
  inputs.mosey.url = "github:danielbodart/mosey/vX.Y.Z"; # a release tag

  # in your NixOS configuration:
  imports = [ inputs.mosey.nixosModules.default ];
  programs.mosey.enable = true;
  programs.mosey.gnome.searchProvider.enable = true;
}
```

`programs.mosey.enable` installs `mosey` and opens UDP 60000-61000
(`programs.mosey.openFirewall`, on by default, as for mosh). It changes
nothing else. The search provider is off until you turn it on.

Two options change how the provider opens and lists sessions:

- `programs.mosey.gnome.searchProvider.terminal` is the terminal
  command. The default (`null`) uses the order in "Terminal selection".
- `programs.mosey.gnome.searchProvider.desktopId` is the app that the
  results show under. The default is `mosey.desktop`, which the module
  installs. If you give a different app, the module does not install
  `mosey.desktop`.

For example, for a GNOME Console that always runs mosey:

```nix
programs.mosey.gnome.searchProvider = {
  enable = true;
  terminal = "kgx";
  desktopId = "org.gnome.Console.desktop";
};
```

Log out and log in again so GNOME Shell loads the new search provider.

## Icon

`icons/hicolor/<N>x<N>/apps/mosey.png` are the standard hicolor theme
sizes, resized with alpha preserved from the 1254px `icon.png` at the
repo root. Regenerate them after changing `icon.png`:

```sh
for s in 16 22 24 32 48 64 128 256 512; do
  magick icon.png -filter Lanczos -resize ${s}x${s} -strip \
    PNG32:gnome-search-provider/icons/hicolor/${s}x${s}/apps/mosey.png
done
```

## Tests

Run the unit tests with standard Python (no live GNOME Shell needed):

```sh
python3 -m unittest discover -s gnome-search-provider -v
```
