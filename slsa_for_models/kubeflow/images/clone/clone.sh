#!/bin/bash
############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: scriptTemplate [h|u|p|c|t]"
   echo "options:"
   echo "u     Url of the repo to clone"
   echo "t     Target of the repo to clone"
   echo "p     Path to the url result"
   echo "c     Path to commit result"
   echo "h       Print this Help."
   echo
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################

url=""
resultPathUrl=""
resultPathCommit=""

############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts ":h:u:p:c:t:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      u) # clone url
	 url=$OPTARG;;
      p) # result path url
	 resultPathUrl=$OPTARG;;
      c) # result path commit
	 resultPathCommit=$OPTARG;;
      t) # result path commit
	 target=$OPTARG;;
      \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

echo "cloning $url into ${target}"
git clone ${url} ${target}
cd ${target}
RESULT_SHA=$(git rev-parse HEAD) 
printf "%s" "${RESULT_SHA}" > ${resultPathCommit}
printf "%s" "${url}" > ${resultPathUrl}
