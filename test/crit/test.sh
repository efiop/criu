images_list=$(ls -1 *.img)

function _exit {
	if [ $? -ne 0 ]; then
		echo "FAIL"
		exit -1
	fi
}

for x in $images_list
do
	echo "=== $x"
	if [[ $x == pages* ]]; then
		echo "skip"
		continue
	fi

	echo "  -- to json"
	../../crit convert -o "$x"".json" --format nice < $x || _exit $?
	echo "  -- to img"
	../../crit convert -i "$x"".json" > "$x"".json.img" || _exit $?
	echo "  -- cmp"
	cmp $x "$x"".json.img" || _exit $?

	echo "=== done"
done
