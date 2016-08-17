



function dra_commands {
    echo -e "${no_color}"
    node_modules_dir=`npm root`

    dra_grunt_command="grunt --gruntfile=$node_modules_dir/grunt-idra3/idra.js"
    dra_grunt_command="$dra_grunt_command -testResult=\"$1\""
    dra_grunt_command="$dra_grunt_command -env=\"$2\""
    dra_grunt_command="$dra_grunt_command -runtime=\"$3\""
    dra_grunt_command="$dra_grunt_command -stage=\"$5\""

    debugme echo -e "dra_grunt_command with tool, log, env, & stage: \n\t$dra_grunt_command"

    if [ -n "$4" ] && [ "$4" != " " ]; then

        debugme echo -e "\tartifact: '$4' is defined and not empty"
        dra_grunt_command="$dra_grunt_command -artifact=\"$4\""
        debugme echo -e "\tdra_grunt_command: \n\t\t$dra_grunt_command"

    else
        debugme echo -e "\tartifact: '$4' is not defined or is empty"
        debugme echo -e "${no_color}"
    fi


    debugme echo -e "FINAL dra_grunt_command: $dra_grunt_command"
    debugme echo -e "${no_color}"


    eval "$dra_grunt_command --no-color"
    GRUNT_RESULT=$?

    debugme echo "GRUNT_RESULT: $GRUNT_RESULT"

    if [ $GRUNT_RESULT -ne 0 ]; then
        exit 1
    fi
    
    echo -e "${no_color}"
}










dir=`pwd`
export DRA_LOG_FILE="$dir/appscan_*.xml"



if [ -n "${ENV_NAME}" ] && [ "${ENV_NAME}" != " " ] && \
    [ -n "${APP_NAME}" ] && [ "${APP_NAME}" != " " ]; then

    if [ -n "${DRA_LOG_FILE}" ] && [ "${DRA_LOG_FILE}" != " " ]; then

        for file in ${DRA_LOG_FILE}
        do
            filename=$(basename "$file")
            extension="${filename##*.}"
            filename="${filename%.*}"

            dra_commands "$file" "${ENV_NAME}" "${APP_NAME}" "$filename.$extension" "codescan"
        done

    else
        echo -e "${no_color}"
        echo -e "${red}Location must be declared."
        echo -e "${no_color}"
    fi

else
    echo -e "${no_color}"
    echo -e "${red}Environment Name and Application Name must be declared."
    echo -e "${no_color}"
fi
