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
while getopts ":h:r:w:s:m:d:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      r) # requirements path
	 requirements=$OPTARG;;
      w) # workingDir
	 workingDir=$OPTARG;;
      s) # source code path
	 sourcePath=$OPTARG;;
      d) # result path digest
	 resultPathDigest=$OPTARG;;
      m) # model name 
	 model=$OPTARG;;
      \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

cd ${workingDir}
python -m pip install --require-hashes -r ${requirements}
python ${sourcePath} ${model}
sha256sum ${model} | awk '{print $1}' | tr -d '\n' | tee ${resultPathDigest}
echo "done..."
echo ${workingDir}
ls -lh
