.PHONY: all, clean

all:
	@mkdir CA
	@openssl ecparam -genkey -name prime256v1 -out ecdsa_key.pem
	@openssl req -new -x509 -days 365 -key ecdsa_key.pem -out cacert.pem -config ./config/CAconfig.cnf

	@openssl x509 -in cacert.pem -text >> ./CA/cacert.txt

	@mkdir CA/private
	@mkdir CA/newcerts
	@touch CA/index.txt CA/serial
	@echo "00" > CA/serial
	@mv cacert.pem CA/
	@mv ecdsa_key.pem CA/private/

	@mkdir user
	@openssl ecparam -name prime256v1 -genkey -noout -out ./user/ecdsa_key.pem
	@openssl ec -in ./user/ecdsa_key.pem -pubout -out ./user/ecdsa_pub.pem
	@openssl ecparam -name prime256v1 -out ./user/prime256v1.pem

	@cp ./config/CAconfig.cnf ./CA/
	@cp ./config/userconfig.cnf ./user/
	@cp ./config/userextensions.cnf ./user/
	@openssl req -new -key ./user/ecdsa_key.pem -out ./user/request.pem -config ./user/userconfig.cnf
	@openssl ca -in ./user/request.pem -out ./user/cert.pem -policy policy_anything -config ./CA/CAconfig.cnf -extfile ./user/userextensions.cnf -days 365


	@mkdir server_arc	
	@openssl ecparam -name prime256v1 -genkey -noout -out ./server_arc/ecdsa_key.pem
	@openssl ec -in ./server_arc/ecdsa_key.pem -pubout -out ./server_arc/ecdsa_pub.pem
	@openssl ecparam -name prime256v1 -out ./server_arc/prime256v1.pem

	@cp ./config/arcconfig.cnf ./server_arc/
	@cp ./config/arcextensions.cnf ./server_arc/
	@openssl req -new -key ./server_arc/ecdsa_key.pem -out ./server_arc/request.pem -config ./server_arc/arcconfig.cnf
	@openssl ca -in ./server_arc/request.pem -out ./server_arc/cert.pem -policy policy_anything -config ./CA/caconfig.cnf -extfile ./server_arc/arcextensions.cnf -days 365

	@mkdir server_residence
	@openssl ecparam -name prime256v1 -genkey -noout -out ./server_residence/ecdsa_key.pem
	@openssl ec -in ./server_residence/ecdsa_key.pem -pubout -out ./server_residence/ecdsa_pub.pem
	@openssl ecparam -name prime256v1 -out ./server_residence/prime256v1.pem

	@cp ./config/server_residenceconfig.cnf ./server_residence/
	@cp ./config/server_residenceextensions.cnf ./server_residence/
	@openssl req -new -key ./server_residence/ecdsa_key.pem -out ./server_residence/request.pem -config ./server_residence/server_residenceconfig.cnf
	@openssl ca -in ./server_residence/request.pem -out ./server_residence/cert.pem -policy policy_anything -config ./CA/caconfig.cnf -extfile ./server_residence/server_residenceextensions.cnf -days 365

	@mkdir server_isee	
	@openssl ecparam -name prime256v1 -genkey -noout -out ./server_isee/ecdsa_key.pem
	@openssl ec -in ./server_isee/ecdsa_key.pem -pubout -out ./server_isee/ecdsa_pub.pem
	@openssl ecparam -name prime256v1 -out ./server_isee/prime256v1.pem

	@cp ./config/server_iseeconfig.cnf ./server_isee/
	@cp ./config/server_iseeextensions.cnf ./server_isee/
	@openssl req -new -key ./server_isee/ecdsa_key.pem -out ./server_isee/request.pem -config ./server_isee/server_iseeconfig.cnf
	@openssl ca -in ./server_isee/request.pem -out ./server_isee/cert.pem -policy policy_anything -config ./CA/caconfig.cnf -extfile ./server_isee/server_iseeextensions.cnf -days 365

clean:
	rm -r ./user/* && rmdir ./user
	rm -r ./CA/* && rmdir ./CA
	rm -r ./server_isee/* && rmdir ./server_isee
	rm -r ./server_residence/* && rmdir ./server_residence
	rm -r ./server_arc/* && rmdir ./server_arc
