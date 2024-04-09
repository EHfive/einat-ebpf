{ config, pkgs, lib, ... }:
with lib;
let
  cfg = config.services.einat;
  configFormat = pkgs.formats.toml { };
  configFile =
    if cfg.configFile != null
    then cfg.configFile
    else configFormat.generate "config.toml" cfg.config;
in
{
  options.services.einat = {
    enable = mkEnableOption "einat service";
    package = mkPackageOption pkgs "einat" { default = [ "einat" ]; };
    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The absolute path to the configuration file.";
    };
    config = mkOption {
      type = configFormat.type;
      default = { };
      description = "The configuration attribute set.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = (cfg.configFile != null) -> (cfg.config == { });
      message = "Either but not both `configFile` and `config` should be specified for einat.";
    }];

    systemd.services.einat = {
      description = "einat service";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/einat -c ${configFile}";
      };
    };

    environment.systemPackages = [ cfg.package ];
  };
}
