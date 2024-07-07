{ naersk
, lib
, rustPlatform
, pkg-config
, rustfmt
, llvmPackages
, elfutils
, zlib
, enableIpv6 ? true
}:
naersk.buildPackage {
  src = ../.;

  nativeBuildInputs = [
    pkg-config
    rustfmt
    llvmPackages.clang-unwrapped
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
