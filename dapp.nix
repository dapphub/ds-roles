dapp: with dapp; solidityPackage {
  name = "ds-roles";
  deps = with dappsys; [ds-auth ds-test];
  src = ./src;
}
