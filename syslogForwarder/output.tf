# version 0.1 #

output "syslogForwarder-VM_name" {
  value = azurerm_linux_virtual_machine.syslogForwarder-VM.name
}

output "syslogForwarder-VM_id" {
  value = azurerm_linux_virtual_machine.syslogForwarder-VM.id
}
