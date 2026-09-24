# restic, optionally with the base OS packages upgraded. Upstream images can lag
# behind Alpine security fixes; rebuilding with `apk upgrade` picks them up.
ARG BASE_IMAGE=restic/restic:0.19.1
FROM ${BASE_IMAGE}
ARG APPLY_OS_UPDATES=false
RUN if [ "$APPLY_OS_UPDATES" = "true" ]; then apk upgrade --no-cache; fi
