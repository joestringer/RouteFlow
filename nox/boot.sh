#! /bin/sh -e

have_ext=$(if test -e src/nox/ext/Makefile.am; then echo yes; else echo no; fi)
for opt
do
    case $opt in
        (--apps-core) core_only=yes ;;
        (--enable-ext) have_ext=yes ;;
        (--disable-ext) have_ext=no ;;
        (--help) cat <<EOF
$0: bootstrap NOX from a Git repository
usage: $0 [OPTIONS]
The recognized options are:
  --enable-ext      include noxext
  --disable-ext     exclude noxext
  --apps-core       only build with core apps
By default, noxext is included if it is present.
EOF
        exit 0
        ;;
        (*) echo "unknown option $opt; use --help for help"; exit 1 ;;
    esac
done

# Enable or disable ext.
if test "$have_ext" = yes; then
    echo 'Enabling noxext...'
    cat debian/control.in src/nox/ext/debian/control.in > debian/control
    for d in $(cd src/nox/ext/debian && git ls-files --exclude-from=debian/dontlink)
    do
        test -e debian/$d || ln -s ../src/nox/ext/debian/$d debian/$d
        if ! fgrep -q $d debian/.gitignore; then
            echo "Adding $d to debian/.gitignore"
            (cat debian/.gitignore && printf '/%s' "$d") \
		| LC_ALL=C sort > tmp$$ \
                && mv tmp$$ debian/.gitignore
        fi
    done
else
    echo 'Disabling noxext...'
    rm -f debian/rules.ext
    cat debian/control.in > debian/control
fi

if test "$core_only" = yes; then
    echo 'building with only core apps'
    cat configure.ac.in | sed -e "s/APPS_ID/core/" | sed -e "s/TURN_ON_NETAPPS/no/" | sed -e "s/TURN_ON_UIAPPS/no/" > configure.ac
    echo "AC_CONFIG_FILES([ " >> configure.ac
    find . -path "*Makefile.am" | grep -v "\<apache-log4cxx\/" | grep -v \
    "\<ext\>" | grep -v "\<netapps\>" | grep -v "\<uiapps\>" \
    | sed -e "s/\.\<am\>//" | sed -e "s/\.\///" \
    >> configure.ac
    echo "])  " >> configure.ac
    echo "AC_OUTPUT  " >> configure.ac
else    
    echo 'building with all core apps'
    cat configure.ac.in | sed -e "s/APPS_ID/full/" | sed -e "s/TURN_ON_NETAPPS/yes/" | sed -e "s/TURN_ON_UIAPPS/yes/" > configure.ac
    echo "AC_CONFIG_FILES([ " >> configure.ac
    find . -path "*Makefile.am" | grep -v "\<apache-log4cxx\/" | grep -v \
    "\<ext\>" \
    | sed -e "s/\.\<am\>//" | sed -e "s/\.\///" \
    >> configure.ac
    echo "])  " >> configure.ac
    echo "AC_OUTPUT  " >> configure.ac
fi    

# Bootstrap configure system from .ac/.am files
autoreconf -Wno-portability --install -I `pwd`/config --force

#(cd src/nox/thirdparty/apache-log4cxx ; ./autogen.sh)
