$(call add-hdrs,fd_gravity.h fd_gravity_wire.h)
$(call add-objs,fd_gravity_wire,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_gravity_wire,fuzz_gravity_wire,fd_discof fd_disco fd_util)
endif

define FD_GRAVITY_VERSION_H
#define FD_GRAVITY_BRANCH_CSTR "$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)"
#define FD_GRAVITY_DIRTY       $(shell git status --porcelain --untracked-files=no 2>/dev/null | grep -q . && echo 1 || echo 0)
endef
ifneq ($(if $(wildcard src/discof/gravity/fd_gravity_version.h),$(file <src/discof/gravity/fd_gravity_version.h)),$(FD_GRAVITY_VERSION_H))
$(file >src/discof/gravity/fd_gravity_version.h,$(FD_GRAVITY_VERSION_H))
endif

ifdef FD_HAS_HOSTED
ifdef FD_HAS_DOUBLE
$(call add-objs,fd_gravity_tile,fd_discof)
endif
endif
