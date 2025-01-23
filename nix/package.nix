{
  naersk,
  lib,
  rustPlatform,
  pkg-config,
  llvmPackages,
  bpftools,
  libbpf,
  elfutils,
  zlib,
  enableIpv6 ? true,
}:
naersk.buildPackage {
  src = ../.;

  nativeBuildInputs = [
    pkg-config
    llvmPackages.clang-unwrapped
    bpftools
    rustPlatform.bindgenHook
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
