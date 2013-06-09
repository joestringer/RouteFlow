#!/bin/sh

RYU_GIT="https://github.com/joestringer/ryu-rfproxy.git"
RYU_BRANCH="origin/master"

RYU_DEPS="python-gevent python-webob python-routes"

get_ryu() {
    # TODO: This recommendation should be revisited after the ovs-1.10+ release
    if [ "$OVS_VERSION" != "git" ]; then
        print_status "We recommend using ovs-git with Ryu for OF1.2+ Support" \
            $YELLOW
    fi

    pkg_install "$MONGO_DEPS"
    print_status "Fetching Ryu controller"

    if [ $FETCH_ONLY -ne 1 ]; then
        $SUPER pip install oslo.config ryu || fail "Failed to fetch ryu controller"
    fi

    fetch "ryu-" "rfproxy" $RYU_GIT $RYU_BRANCH ||
        fail "Couldn't fetch ryu-rfproxy"
    $DO cd -
}
