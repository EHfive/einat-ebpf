{ naersk
, lib
, rustPlatform
, pkg-config
, rustfmt
, clang
, elfutils
, zlib
, enableIpv6 ? false
}:
naersk.buildPackage {
  src = ../.;

  nativeBuildInputs = [
    pkg-config
    rustfmt
    clang
    rustPlatform.bindgenHook
    elfutils
    zlib
  ];

  buildInputs = [
    elfutils
    zlib
  ];

  buildFeatures = lib.optionals enableIpv6 [ "ipv6" ];

  meta = with lib; {
    description = "An eBPF-based Endpoint-Independent(Full Cone) NAT";
    homepage = "https://github.com/EHfive/einat-ebpf";
    license = licenses.gpl2Only;
    platforms = platforms.linux;
  };
}
