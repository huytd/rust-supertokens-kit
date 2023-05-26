backend:
	RUST_LOG=debug cargo watch -i '*.tsx?' -x run

frontend:
	cd web && yarn && NODE_ENV=development yarn build --watch