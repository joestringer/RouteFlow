#bashrc setup
if [ -z "$NOXPATH" ]
then
    if [ -d "./src/nox" ]
    then
	echo export NOXPATH=${PWD%/*} >> ~/.bashrc
	echo -e export PATH=\$PATH:\$NOXPATH/noxcore/src/utilities/ >> ~/.bashrc
	echo -e export PYTHONPATH=\$NOXPATH/noxcore/src/pylib >> ~/.bashrc
    fi
fi
