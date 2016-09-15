#!/bin/bash

function dra_commands {
    echo -e "${no_color}"

    dra_grunt_command="grunt --gruntfile=$NPM_ROOT_DIR/grunt-idra3/idra.js"
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


    eval "$dra_grunt_command -f --no-color"
    GRUNT_RESULT=$?

    debugme echo "GRUNT_RESULT: $GRUNT_RESULT"

    if [ $GRUNT_RESULT -ne 0 ]; then
        exit 1
    fi
    
    echo -e "${no_color}"
}






echo ""

for fullReport in appscan-*.xml;
do

    # full report location
    export DRA_LOG_FILE="$EXT_DIR/$fullReport"
    # summary report location. Replace appscan-app.zip with appscan-app.json.
    export DRA_SUMMARY_FILE="$EXT_DIR/${fullReport%.xml}.json"

    if [ -n "${ENV_NAME}" ] && [ "${ENV_NAME}" != " " ] && \
        [ -n "${APP_NAME}" ] && [ "${APP_NAME}" != " " ]; then

        # upload the full appscan report
        dra_commands "${DRA_LOG_FILE}" "${ENV_NAME}" "${APP_NAME}" "${fullReport}" "codescan"
        # upload the summary appscan report
        dra_commands "${DRA_SUMMARY_FILE}" "${ENV_NAME}" "${APP_NAME}" "${fullReport%.xml}.json" "codescansummary"

    else
        echo -e "${no_color}"
        echo -e "${red}Deployment Risk Analytics requires the Environment Name (ENV_NAME) and Application Name (APP_NAME) variables."
        echo -e "${no_color}"
    fi
    
done
