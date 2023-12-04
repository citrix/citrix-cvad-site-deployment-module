locals {
  setup_folder_path          = "../Setup/"
  cert_authority_common_name = replace("${var.active_directory_domain_name}-CA", ".", "-")
}
