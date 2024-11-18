{
  naersk,
  lib,
  rustPlatform,
  pkg-config,
  rustfmt,
  llvmPackages,
  libbpf,
  elfutils,
  zlib,
  enableIpv6 ? true,
}:
naersk.buildPackage {
  src = ../.;

  nativeBuildInputs = [
    pkg-config
    rustfmt
    llvmPackages.clang-unwrapped
    llvmPackages.bintools-unwrapped
    rustPlatform.bindgenHook
    elfutils
    zlib
  ];

  buildInputs = [
    libbpf
    elfutils
    zlib
  ];

  buildFeatures = [
    "aya"
    "libbpf"
  ] ++ lib.optionals enableIpv6 [ "ipv6" ];

  meta = with lib; {
    description = "An eBPF-based Endpoint-Independent(Full Cone) NAT";
    homepage = "https://github.com/EHfive/einat-ebpf";
    license = licenses.gpl2Only;
    platforms = platforms.linux;
  };
}
