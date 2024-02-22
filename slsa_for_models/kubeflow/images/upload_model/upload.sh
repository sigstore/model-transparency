#! /bin/bash
############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: scriptTemplate [h|r|s|m|d]"
   echo "options:"
   echo "r     Requirements path"
   echo "s     source code path"
   echo "m     model name"
   echo "d     Path to digest result"
   echo "h       Print this Help."
   echo
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################

############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts ":h:r:w:c:s:l:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      r) # result path url
	 resultPathUrl=$OPTARG;;
      w) # workingDir
	 workingDir=$OPTARG;;
      c) # result path commit
	 resultPathCommit=$OPTARG;;
      s) # source code path
	 SOURCE=$OPTARG;;
      l) # result path digest
	 LOCATION=$OPTARG;;
      \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

echo ${workingDir}
cd ${workingDir}
ls -lh
echo "source: ${SOURCE}"
echo "location: ${LOCATION}"
gsutil cp "${SOURCE}" "${LOCATION}"
SHA256=$(sha256sum ${SOURCE} | awk '{print $1}' | tr -d '\n')
printf "sha256:%s" "${SHA256}" > ${resultPathCommit}
printf "md5:%s" "${LOCATION}" > ${resultPathUrl}
