.PHONY: provision capture

provision:
	ansible-playbook site.yml

capture:
	ansible sensor -b -m command -a 'netforge-tpot-capture /var/lib/netforge-evidence'
