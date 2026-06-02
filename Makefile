COMPOSE ?= podman-compose
PROJECT ?= astra-cdn

.PHONY: up up-minio up-multi-edge global-edge-plan cloud-deploy cloud-verify down logs reset-data clean clean-images smoke test bench fmt

up:
	$(COMPOSE) -f podman-compose.yml up --build

up-minio:
	ORIGIN_STORAGE_MODE=s3 DASHBOARD_STORAGE_MODE=s3 \
	ORIGIN_S3_ENDPOINT=http://minio:9000 DASHBOARD_S3_ENDPOINT=http://minio:9000 \
	ORIGIN_S3_BUCKET=astra-cdn-assets DASHBOARD_S3_BUCKET=astra-cdn-assets \
	ORIGIN_S3_ACCESS_KEY_ID=astracdn DASHBOARD_S3_ACCESS_KEY_ID=astracdn \
	ORIGIN_S3_SECRET_ACCESS_KEY=astracdn-local-minio-secret DASHBOARD_S3_SECRET_ACCESS_KEY=astracdn-local-minio-secret \
	$(COMPOSE) -f podman-compose.yml --profile object-storage up --build

up-multi-edge:
	$(COMPOSE) -f podman-compose.yml --profile multi-edge up --build

global-edge-plan:
	cd deploy/opentofu && tofu init && tofu plan -var-file=examples/production.tfvars.example

cloud-deploy:
	./scripts/cloud-deploy.sh

cloud-verify:
	./scripts/cloud-verify.sh

down:
	$(COMPOSE) -f podman-compose.yml down

logs:
	$(COMPOSE) -f podman-compose.yml logs -f

reset-data:
	@$(COMPOSE) -f podman-compose.yml down --volumes --remove-orphans >/dev/null 2>&1 || true

clean:
	@$(COMPOSE) -f podman-compose.yml down --remove-orphans >/dev/null 2>&1 || true

clean-images:
	podman images --format '{{.Repository}} {{.ID}}' | awk '$$1 ~ /^localhost\/$(PROJECT)_/ { print $$2 }' | xargs -r podman rmi

smoke:
	./scripts/smoke-test.sh

test:
	go test ./...

bench:
	go test -bench=. -benchmem ./services/edge/cmd/edge ./services/inference/cmd/inference

fmt:
	gofmt -w services
