{ solidityPackage, dappsys }: solidityPackage {
  name = "ds-roles";
  deps = with dappsys; [ds-auth ds-test];
  src = ./src;
}
