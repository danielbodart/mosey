# The GNOME Shell search provider (../gnome-search-provider) as a package:
# the script with a Python that has PyGObject, its D-Bus service with Exec
# pointing here, the search-provider .ini, the icons, and mosey.desktop
# when the results are listed under it. The NixOS module
# (./module.nix, programs.mosey.gnome.searchProvider) installs it.
{ lib
, stdenvNoCC
, python3
, glib
, gobject-introspection
, wrapGAppsNoGuiHook
, mosey
  # The command a result opens in, before `-- mosey -s NAME ...`
  # (MOSEY_TERMINAL); null is the provider's own choice, kgx, then
  # gnome-terminal, then ptyxis.
, terminal ? null
  # The desktop file the results are listed under in Overview search.
, desktopId ? "mosey.desktop"
}:

stdenvNoCC.mkDerivation {
  pname = "mosey-gnome-search-provider";
  inherit (mosey) version;
  src = ../gnome-search-provider;
  dontBuild = true;
  nativeBuildInputs = [ wrapGAppsNoGuiHook gobject-introspection ];
  buildInputs = [ (python3.withPackages (ps: [ ps.pygobject3 ])) glib ];

  # MOSEY_BIN is this package's mosey, not whatever D-Bus activation's
  # PATH holds, so the sessions listed are the ones this mosey's server
  # runs and a result opens with the same binary.
  preFixup = ''
    gappsWrapperArgs+=(--set MOSEY_BIN ${lib.getExe mosey})
  '' + lib.optionalString (terminal != null) ''
    gappsWrapperArgs+=(--set MOSEY_TERMINAL ${lib.escapeShellArg terminal})
  '';

  installPhase = ''
    runHook preInstall
    install -Dm0755 mosey-search-provider $out/bin/mosey-search-provider
    install -Dm0644 mosey-search-provider.ini \
      $out/share/gnome-shell/search-providers/mosey-search-provider.ini
    substituteInPlace $out/share/gnome-shell/search-providers/mosey-search-provider.ini \
      --replace-fail "DesktopId=mosey.desktop" "DesktopId=${desktopId}"
    install -Dm0644 org.mosey.SearchProvider.service \
      $out/share/dbus-1/services/org.mosey.SearchProvider.service
    substituteInPlace $out/share/dbus-1/services/org.mosey.SearchProvider.service \
      --replace-fail "Exec=/usr/bin/env mosey-search-provider" "Exec=$out/bin/mosey-search-provider"
    mkdir -p $out/share/icons
    cp -r icons/hicolor $out/share/icons/
  '' + lib.optionalString (desktopId == "mosey.desktop") ''
    # mosey's own launcher, only when the results are listed under it: a
    # second app-grid entry beside the app they are listed under would
    # only be clutter. It must never be NoDisplay=true, or GNOME Shell
    # silently ignores the provider (see mosey.desktop).
    install -Dm0644 mosey.desktop $out/share/applications/mosey.desktop
    substituteInPlace $out/share/applications/mosey.desktop \
      --replace-fail "Exec=kgx -- mosey " "Exec=${if terminal == null then "kgx" else terminal} -- ${lib.getExe mosey} "
  '' + ''
    runHook postInstall
  '';

  meta = {
    description = "GNOME Shell search provider for mosey sessions";
    homepage = "https://github.com/danielbodart/mosey";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "mosey-search-provider";
  };
}
