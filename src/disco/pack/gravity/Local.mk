ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_gravity_wire.h fd_gravity_sess.h fd_gravity.h)
$(call add-objs,fd_gravity_wire fd_gravity_sess fd_gravity,fd_disco)
$(call make-unit-test,test_gravity_wire,test_gravity_wire,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_gravity_sess,test_gravity_sess,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_gravity,test_gravity,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_gravity_wire)
$(call run-unit-test,test_gravity_sess)
$(call run-unit-test,test_gravity)
endif
endif
