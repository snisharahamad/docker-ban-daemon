
package main

import "os/exec"

// Firewall définit ce que l'agent a besoin de faire sur le pare-feu.
type Firewall interface {
	Reset() error
	Ban(ip string) error
	Unban(ip string) (bool, error)
}

// IPTablesFirewall est la vraie implémentation utilisée en production.
type IPTablesFirewall struct{}

func (f *IPTablesFirewall) Reset() error {
	if err := exec.Command("iptables", "-F", "DOCKER-USER").Run(); err != nil {
		return err
	}
	return exec.Command("iptables", "-A", "DOCKER-USER", "-j", "RETURN").Run()
}

func (f *IPTablesFirewall) Ban(ip string) error {
	if exec.Command("iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP").Run() == nil {
		return nil // déjà bannie
	}
	return exec.Command("iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP").Run()
}

func (f *IPTablesFirewall) Unban(ip string) (bool, error) {
	removed := false
	for exec.Command("iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP").Run() == nil {
		removed = true
	}
	return removed, nil
}
