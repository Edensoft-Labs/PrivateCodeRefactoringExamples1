#!/usr/bin/env python3

"""
Copyright 2020 Wirepath Home Systems, LLC. All Rights Reserved.
"""

import argparse
import codecs
import datetime
import glob
from io import BytesIO
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional
import zipfile

from lxml import etree

import build_c4z as c4z

## True if Lua files should be squished into a single file; false if not.
## See the following for more on Lua squishing:
## - https://matthewwild.co.uk/projects/squish/readme.html
## - https://github.com/LuaDist/squish
global squishLua
## True if the driver being built is a C4I driver; false if not.
global c4i

## Packages Control4 .c4z driver files.
class DriverPackager(object):
    ## Initializes a driver packager according to supplied arguments.
    ## \param[in]   arguments - Arguments for configuring the driver packager.
    def __init__(self, arguments: argparse.Namespace):
        # INTIALIZE FIELDS.
        ## True if verbose output should be printed; false if not.
        self.verbose: bool = arguments.verbose
        ## Directory path where c4z input files are placed.
        self.source_directory_path: str = arguments.source_directory_path
        ## Directory path where c4z output files are placed.
        self.destination_directory_path: str = arguments.destination_directory_path
        ## Optional filename of the manifest XML file.
        self.manifest_xml_filename: Optional[str] = arguments.manifest_xml_filename
        ## Raw bytes for the driver XML file.
        self.bytes_io = BytesIO()
        
        ## True if the c4z should be unzipped in the destination location; false if not.
        self.unzip: bool = arguments.unzip
        ## True to allow executing in a Lua command window; false if not.
        ## Enabling this will add `C4:AllowExecute(true)` to the driver Lua file
        ## and mark it as a development driver.
        self.allow_execute: bool = arguments.allowexecute
        ## True to update the driver-modified date in XML; false to not.
        self.update_modified: bool = arguments.update_modified

        ## Optional driver version to update the driver to.
        ## False if no driver version updates are needed.
        self.driver_version: str | bool = False
        # The driver version argument comes from the next arguments, so it will be a list if specified,
        # but only a single version is expected.
        driver_version_arguments: Optional[list[str]] = getattr(arguments, 'driver_version', None)
        driver_version_exists: bool = driver_version_arguments is not None
        if driver_version_exists:
            # The actual driver version should be the first and only argument in this list.
            SINGLE_DRIVER_VERSION_ARGUMENT_INDEX: int = 0
            self.driver_version = arguments.driver_version[SINGLE_DRIVER_VERSION_ARGUMENT_INDEX]
        else:
            self.Log("Version argument not found, skipping version update.")
            self.driver_version = False

        # ENSURE THE DESTINATION DIRECTORY EXISTS.
        os.makedirs(self.destination_directory_path, exist_ok=True)

    ## Squishes Lua files into a single file.
    ## See the following for more on Lua squishing:
    ## - https://matthewwild.co.uk/projects/squish/readme.html
    ## - https://github.com/LuaDist/squish
    ## \param[in]   root_directory_path - Path to the root directory of Lua files to squish.
    ## \throws  Exception - If an error occurs.
    def Squish(self, root_directory_path: str):
        # SAVE IMPORTANT ENVIRONMENT INFORMATION BEFORE SQUISHING.
        # These will be overwritten below and need to be restored.
        self.Log("Squishing Lua source...")
        original_path_environment_variable_value: str = os.environ['PATH']
        original_current_working_directory_path: str = os.getcwd()
        print('Saved Directory: '+original_current_working_directory_path)

        # SWITCH TO THE ROOT DIRECTORY OF THE LUA FILES TO SQUISH.
        os.chdir(root_directory_path)
        print('Current Directory: '+os.getcwd())

        # FORM THE COMMAND FOR SQUISHING LUA FILES.
        lua_squish_command: list[str] = ['luajit']

        # Depending on whether this packager is being run as a pre-built executable or not,
        # the next part of the command needs to be formed differently.
        running_as_executable: bool = getattr(sys, 'frozen', False)
        if running_as_executable:
            # LOOK FOR SQUISH IN THE SAME DIRECTORY AS THE EXECUTABLE.
            executable_path: str = os.path.realpath(sys.executable)
            executable_directory_path: str = os.path.dirname(executable_path)
            squish_command_path: str = os.path.join(executable_directory_path, "squish")
            lua_squish_command.append(squish_command_path)

            # ENSURE FILES NEXT TO THE EXECUTABLE CAN BE FOUND.
            os.environ['PATH'] = executable_directory_path + ";" + oldPath
        else:
            # LOOK FOR SQUISH IN THE SAME DIRECTORY AS THIS SCRIPT FILE.
            current_filepath: str = os.path.realpath(__file__)
            current_file_directory_path: str = os.path.dirname(current_filepath)
            squish_command_path: str = os.path.join(current_file_directory_path, "squish")
            lua_squish_command.append(squish_command_path)

            # ENSURE FILES NEXT TO THIS SCRIPT CAN BE FOUND.
            os.environ['PATH'] = current_file_directory_path + os.pathsep + oldPath

        # A few additional options are added to the command.
        # cmdLine.append('-q')
        lua_squish_command.append('--no-minify')

        # Verbose logging should be used for Lua squishing if enabled.
        if self.verbose:
            lua_squish_command.append('--vv')

        # The squish command needs to be aware of the directory being squished.
        lua_squish_command.append(root_directory_path)

        # RUN THE COMMAND TO SQUISH LUA FILES.
        try:
            # PROVIDE VISIBILITY INTO THE LUA COMMAND BEING RUN.
            print('Root Directory: '+root_directory_path)
            print('CommandLine: ')
            print(' '.join(lua_squish_command))

            # RUN THE LUA SQUISH COMMAND AND AUTOMATICALLY CHECK FOR ERRORS.
            subprocess.check_call(lua_squish_command, stderr=subprocess.STDOUT)
        except OSError as exception:
            raise Exception(f"DriverPackager: Error squishing lua {exception}")
        except subprocess.CalledProcessError as exception:
            raise Exception(
                f"DriverPackager: Lua squish failed: {exception} while processing {root_directory_path}")
        finally:
            # RESTORE ORIGINAL ENVIRONMENT SETTINGS.
            os.environ["PATH"] = original_path_environment_variable_value
            os.chdir(original_current_working_directory_path)

    ## Creates a driver package from a manifest file.
    ## \param[in]   manifest_xml_filepath - The path to the manifest file.
    ## \return  A return code from trying to create the driver package.
    ##      0 indicates success; any other value indicates failure.
    def CreateFromManifest(self, manifest_xml_filepath: str) -> int:
        try:
            # READ THE ROOT NODE FROM THE MANIFEST XML FILE.
            manifest_xml_tree = etree.parse(manifest_xml_filepath)
            manifest_xml_root_element = manifest_xml_tree.getroot()

            # PARSE XML TO CREATE THE PACKAGE.
            try:
                self.ParseXml(manifest_xml_root_element, self.source_directory_path)
                # If no exception occurs, then creation should be successful.
                SUCCESS_RETURN_CODE: int = 0
                return SUCCESS_RETURN_CODE
            except Exception as exception:
                # PROVIDE VISIBILITY INTO THE SPECIFIC ERROR.
                self.Log(exception)
                XML_PARSING_ERROR_CODE: int = 255
                return XML_PARSING_ERROR_CODE

        except IOError as exception:
            # PROVIDE VISIBILITY INTO THE SPECIFIC ERROR.
            self.Log(exception)
            return exception.errno
        except etree.ParseError as exception:
            # PROVIDE VISIBILITY INTO THE SPECIFIC ERROR.
            self.Log(f"DriverPackager: Invalid XML ({manifest_xml_filepath}): {exception}")
            return exception.code

    ## Gets the encrypted script filename from the driver XML file.
    ## \param[in]   driver_xml_filepath - Path to the driver XML file to read.
    ## \return  The encrypted script filename.
    ## \throws  Exception - Thrown if the XML file is invalid.
    def GetEncryptFilename(self, driver_xml_filepath: str) -> Optional[str]:
        try:
            # GET THE ROOT ELEMENT OF THE DRIVER XML.
            driver_xml_tree = etree.parse(driver_xml_filepath)
            driver_xml_root_element = driver_xml_tree.getroot()

            # SEARCH FOR SCRIPT ENCRYPTION ELEMENTS.
            c4z_script_file = None
            script_elements = driver_xml_root_element.findall('./config/script')
            for script_element in script_elements:
                # CHECK THE ENCRYPTION FOR THE CURRENT SCRIPT.
                c4z_script_encryption = script_element.attrib.get('encryption')
                if c4z_script_encryption == '2':
                    # Only use the newer encryption.
                    if c4z.squishLua_:
                        # If squishing is enabled, get the output file from the squish tool.
                        c4z_script_file = c4z.GetSquishyOutputFile(self.source_directory_path)
                    else:
                        # Otherwise, get the file name from the script tag attribute.
                        c4z_script_file = script_element.attrib.get('file')

            # RETURN ANY SCRIPT ENCRYPT FILE IF FOUND.
            return c4z_script_file
        except etree.ParseError as exception:
            raise Exception(
                f"DriverPackager: Invalid XML ({driver_xml_filepath}): {exception}")

    ## Cleans up any temporary Lua driver file in the specified directory.
    ## If a temporary file exists, it will be copied to a permanent location.
    ## \param[in]   root_directory_path - Root directory in which to search for a temporary Lua driver file.
    def CleanupTmpFile(self, root_directory_path: str):
        # CHECK IF EXECUTION IN A LUA COMMAND WINDOW WAS ALLOWED.
        if self.allow_execute:
            try:
                # CHECK IF A TEMPORARY LUA FILE EXISTS.
                temporary_driver_lua_filepath: str = os.path.join(root_directory_path, "driver.lua.tmp")
                temporary_driver_lua_file_exists: bool = os.path.exists(temporary_driver_lua_filepath)
                if temporary_driver_lua_file_exists:
                    # COPY THE TEMPORARY LUA FILE TO A FINAL LOCATION.
                    final_driver_lua_filepath: str = os.path.join(root_directory_path, "driver.lua")
                    shutil.copyfile(temporary_driver_lua_filepath, final_driver_lua_filepath)

                    # REMOVE THE TEMPORARY LUA FILE.
                    os.remove(temporary_driver_lua_filepath)
            except Exception as exception:
                self.Log("Unable to remove driver.lua.tmp file or file does not exist")

    def ParseXml(self, xml_root_element, root_directory_path: str):
        c4zDriverXmlFound = False
        c4zScriptFile = ''
        c4zDirs = []
        c4zFiles = []

        # VALIDATE THE ROOT XML ELEMENT.
        is_for_driver_element: bool = (xml_root_element.tag == 'Driver')
        if not is_for_driver_element:
            raise Exception("DriverPackager: Invalid XML: Missing tag 'Driver'")

        driver_type = xml_root_element.attrib.get('type')
        driver_type_specified: bool = driver_type is not None
        if not driver_type_specified:
            raise Exception("DriverPackager: Invalid XML: Missing tag 'type'")

        driver_name = xml_root_element.attrib.get('name')
        driver_name_specified: bool = driver_name is not None
        if driver_name_specified:
            raise Exception("DriverPackager: Invalid XML: Missing tag 'name'")

        # CONFIGURE LUA SQUISHING.
        # An XML boolean needs to be converted to a Python boolean.
        squish_lua: bool = True if xml_root_element.attrib.get(
            'squishLua') == 'true' else False
        c4z.setSquishLua(squish_lua)

        # CONFIGURE SETTINGS FOR C4I DRIVERS.
        c4i = True if driver_type == 'c4i' else False
        if c4i:
            self.bytes_io = None
        c4z.setC4i(c4i)

        # FORM THE C4Z DRIVER FILENAME.
        c4z_filename: str = '.'.join((driverName, driverType))

        # EXECUTE ANY PREPACKAGING COMMANDS.
        prepackage_command_xml_elements = xml_root_element.find('PrepackageCommands')
        prepackage_commands_exist: bool = prepackage_command_xml_elements is not None
        if prepackage_commands_exist:
            # EXECUTE EACH PREPACKAGING COMMAND.
            for prepackage_command_xml_element in prepackage_command_xml_elements:
                # VERIFY THE COMMAND XML IS VALID.
                print(prepackage_command_xml_element.tag, prepackage_command_xml_element.text)
                is_valid_prepackage_command_xml: bool = prepackage_command_xml_element.tag == 'PrepackageCommand'
                if not is_valid_prepackage_command_xml:
                    self.Log(f"Invalid XML: Found tag '{prepackage_command_xml_element.tag}', should be 'PrepackageCommand'")
                    continue

                # EXECUTE THE PREPACKAGING COMMAND.
                # Commands should use the correct path separator for the current OS.
                prepackage_command: str = prepackage_command_xml_element.text.replace("\\", os.path.sep)
                prepackage_command = prepackage_command.replace("/", os.path.sep)
                SUCCESS_RETURN_CODE: int = 0
                prepackage_command_return_code: int = os.system(prepackage_command)
                prepackage_command_succeeded: bool = (prepackage_command_return_code == SUCCESS_RETURN_CODE)
                if prepackage_command_succeeded:
                    raise Exception("Failed to execute prepackage command.")

        # VERIFY THE XML HAS ITEMS.
        item_xml_elements = xml_root_element.find('Items')
        items_exist: bool = item_xml_elements is not None
        if items_exist:
            raise Exception("DriverPackager: Invalid XML: Missing tag 'Items'")

        # ADD LUA EXECUTION ATTRIBUTES IF ENABLED.
        if self.allow_execute:
            # ENABLE EXECUTION IN A LUA COMMAND WINDOW FOR DEVELOPMENT DRIVERS.
            print("C4:AllowExecute(true) being added to file")
            # The original Lua driver file will be backed up to a temporary location.
            original_lua_driver_filepath: str = os.path.join(root_directory_path, "driver.lua")
            temporary_lua_driver_filepath: str = os.path.join(root_directory_path, "driver.lua.tmp")
            shutil.copyfile(original_lua_driver_filepath, temporary_lua_driver_filepath)
            # New settings will be appended to the original Lua driver file.
            with open(original_lua_driver_filepath, "a") as lua_driver_file:
                # ALLOW EXECUTION IN A LUA COMMAND WINDOW.
                lua_driver_file.write("\nC4:AllowExecute(true)\n")
                
                # ENABLE DEVELOPMENT DRIVER FEATURES.
                lua_driver_file.write("\ngIsDevelopmentVersionOfDriver = true\n")

        # PROCESS EACH ITEM.        
        for item_xml_element in item_xml_elements :
            # VERIFY THE ITEM XML IS VALID.
            # It should have the appropriate tag.
            item_xml_element_has_correct_tag: bool = (item_xml_element.tag == 'Item')
            if not item_xml_element_has_correct_tag:
                self.Log(f"Invalid XML: Found tag '{item_xml_element.tag}', should be 'Item'")
                continue

            # VERIFY THE ITEM HAS MANDATORY ATTRIBUTES.
            # A type is required.
            item_type = item_xml_element.attrib.get('type')
            item_type_exists: bool = item_type is not None
            if item_type_exists:
                self.CleanupTmpFile(root_directory_path)
                raise Exception("DriverPackager: Invalid XML: Missing tag 'Item' subtag 'type'")

            # A name is required.
            item_name = item_xml_element.attrib.get('name')
            item_name_exists: bool = item_name is not None
            if item_name_exists:
                self.CleanupTmpFile(root_directory_path)
                raise Exception("DriverPackager: Invalid XML: Missing tag 'Item' subtag 'name'")

            # SKIP EXCLUDED ITEMS.
            # This is an optional attribute and needs to be converted from
            # an XML boolean to a Python boolean.
            # If optional item attribute 'exclude' is True, skip it
            item_excluded: bool = True if item_xml_element.attrib.get(
                'exclude') == str('true').lower() else False
            if item_excluded:
                continue

            # PROCESS THE ITEM ACCORDING TO ITS TYPE.
            if item_type == 'dir':
                # VERIFY THE DIRECTORY ITEM EXISTS WITHIN THE ROOT DIRECTORY.
                directory_path: str = os.path.join(root_directory_path, item_name)
                directory_exists: bool = os.path.exists(directory_path)
                if not directory_exists:
                    self.CleanupTmpFile(root_directory_path)
                    raise Exception(f"DriverPackager: Error, manifest 'dir' Item '{item_name}' does not exist.")

                # CHECK IF THE DIRECTORY SHOULD BE RECURSED INTO.
                recurse = True if item_xml_element.attrib.get(
                    'recurse') == str('true').lower() else False
                
                # GET ANY OPTIONAL C4Z DIRECTORY.
                c4zDir = item_xml_element.attrib.get('c4zDir') if item_xml_element.attrib.get(
                    'c4zDir') != None else ''
                
                # CONFIGURE THE C4Z DIRECTORY ITEM.
                c4zDirs.append(
                    {'c4zDir': c4zDir, 'recurse': recurse, 'name': item_name})

            elif item_type == 'file':
                # REMOVE ANY ENCYPTED EXTENSION FROM THE ITEM NAME.
                if c4zScriptFile:
                    filename_without_last_extension, file_extension = os.path.splitext(item_name)
                    is_encrypted_file: bool = file_extension == '.encrypted'
                    if is_encrypted_file:
                        item_name = filename_without_last_extension

                # VERIFY THE FILE ITEM EXISTS.
                item_filepath: str = os.path.join(root_directory_path, item_name)
                item_file_exists: bool =os.path.exists(item_filepath) 
                if not item_file_exists:
                    self.CleanupTmpFile(root_directory_path)
                    raise Exception(f"DriverPackager: Error, manifest 'file' Item '{item_name}' does not exist in {root_directory_path}'.")

                # GET THE SCRIPT SECTION FROM THE DRIVER XML.
                is_driver_xml_item: bool = (item_name == 'driver.xml')
                if is_driver_xml_item:
                    # TRACK THAT THE DRIVER XML WAS FOUND.
                    c4zDriverXmlFound = True

                    # GET ANY ENCRYPTED SCRIPT FILENAME.
                    c4zScriptFile = self.GetEncryptFilename(item_filepath)

                    # READ THE DRIVER.XML TO DETERMINE IF 'TEXTFILE' ATTRIBUTE EXISTS.
                    driver_xml_tree = etree.parse(item_filepath)
                    driver_xml_root_element = driver_xml_tree.getroot()

                    # The 'textfile' attribute will be under any documentation elements.
                    documentation_xml_elements = driver_xml_root_element.findall('./config/documentation')
                    documentation_xml_elements_exist: bool = len(documentation_xml_elements) > 0

                    if not documentation_xml_elements_exist:
                        # Couldn't find the documentation attribute so there is nothing to do.  Moving on...
                        pass
                    else:
                        # LOOK FOR A 'TEXTFILE' ATTRIBUTE IN THE FIRST DOCUMENTATION ELEMENT.
                        first_documentation_xml_element = driver_xml_root_element.find('./config/documentation')
                        textfile_attribute_exists_in_documentation_element: bool = 'textfile' in first_documentation_xml_element.attrib
                        if textfile_attribute_exists_in_documentation_element:
                            # GET THE TEXTFILE IN THE DOCUMENTATION ELEMENT.
                            textfile: str = first_documentation_xml_element.attrib['textfile']

                            # GET ANY DOCUMENTATION FILE SPECIFIED IN THE XML ELEMENT.
                            documentation_file: Optional[str] = None
                            documentation_file_exists_in_xml_element: bool = 'file' in first_documentation_xml_element.attrib
                            if documentation_file_exists_in_xml_element:
                                docFile = first_documentation_xml_element.attrib['file']

                            # BACKUP THE DRIVER XML FILE.
                            # If the 'textfile' attribute exists, create a backup of the driver.xml (driver.xml.bak) because modifications will need to be made.
                            item_backup_filepath: str = item_filepath + '.bak'
                            shutil.copy(item_filepath, item_backup_filepath)

                            # READ THE CONTENTS OF THE FILE REFERENCE IN THE ABOVE 'TEXTFILE' ATTRIBUTE.
                            # It will ultimately be written to the inner-text of the <documentation> element.
                            textfile_path: str = os.path.join(root_directory_path, textfile)
                            try:
                                codecs.open(textfile_path, 'r')
                            except Exception as ex:
                                self.Log("Unable to find the file " + "'" + textfile + "'" +
                                         " referenced in the 'textfile' attribute of the '<documentation>' element in your driver.xml")
                            finally:
                                textfile_contents = codecs.open(textfile_path, 'r')
                                textfile_lines = textfile_contents.readlines()
                                textfile_contents.close()
                               
                            # REMOVE THE DOCUMENTATION ELEMENTS FOR THE DRIVER XML.
                            # They will be recreated later below.
                            xml_tree = etree.parse(item_filepath)
                            xml_root_driver = xml_tree.getroot()
                            documentation = xml_root_driver.findall('./config/documentation')
                            documentation_exists: bool = documentation is not None
                            if documentation_exists:
                                config = xml_root_driver.find('config')
                                for documentation_element in config.findall('documentation'):
                                    config.remove(documentation_element)

                            # CREATE A NEW DOCUMENTATION ELEMENT WITH THE TEXTFILE CONTENTS.
                            # The contents of the 'textfile' go in the innertext of the '<documentation>' element in the driver.xml.
                            config_xml_element = xml_tree.find('config')
                            new_documentation_xml_element = etree.SubElement(config_xml_element, 'documentation')
                            new_documentation_xml_element.text = ''.join(textfile_lines)

                            # SET DOCUMENTATION FILES FOR C4Z DRIVERS.
                            is_c4z_driver: bool = driver_type == "c4z"
                            if is_c4z_driver:
                                documentation_file_exists: bool = documentation_file is not None
                                if documentation_file_exists:
                                    new_documentation_xml_element.set('file', documentation_file)

                            # WRITE THE CHANGES TO THE XML DOCUMENT.
                            xml_tree.write(item_filepath, pretty_print=True)

                        else:
                            # Couldn't find the textfile attribute so there is nothing to do.  Carry on...
                            pass

                    # SQUISH LUA SOURCE IF THE MANIFEST AND DRIVER.XML AGREE.
                    if squishLua:
                        self.Squish(root_directory_path)

                    # ENSURE C4I DRIVERS ARE BEING BUILT WITH SQUISHED LUA.
                    building_c4i_driver_without_squish_lua: bool = (c4i and not squishLua)
                    if building_c4i_driver_without_squish_lua:
                        self.CleanupTmpFile(root_directory_path)
                        raise Exception(
                            "You are attempting to build a driver of type 'c4i', but 'squishLua' is set to false in the project file/manifest.  This needs to be set to true.")

                # GET ANY OPTIONAL C4Z DIRECTORY.
                c4zDir = item_xml_element.attrib.get('c4zDir') if item_xml_element.attrib.get(
                    'c4zDir') != None else ''
                is_driver_xml_item_for_non_c4i_driver: bool = (item_name == "driver.xml" and not c4i)
                if is_driver_xml_item_for_non_c4i_driver:
                    pass
                else:
                    # TRACK THE ITEM AS BEING FOR C4Z FILES.
                    c4zFiles.append({'c4zDir': c4zDir, 'name': item_name})

        # MAKE SURE THE DRIVER XML WAS FOUND.
        if not c4zDriverXmlFound:
            raise Exception("DriverPackager: Error, manifest 'file' Item 'driver.xml' was not found.")

        # UPDATE THE DRIVER XML.
        driver_xml_filepath: str = os.path.join(root_directory_path, "driver.xml")
        self.UpdateDriverXml(driver_xml_filepath)

        # COMPRESS C4Z DRIVER ITEMS.
        destination_c4z_filepath: str = os.path.join(self.destination_directory_path, c4zName)
        c4z_compression_succeeded: bool = c4z.compressLists(
            destination_c4z_filepath, 
            root_directory_path, 
            c4zDirs, 
            c4zFiles, 
            c4zScriptFile, 
            xmlByteOverride=self.bytes_io.getvalue())
        if not c4z_compression_succeeded:
            raise Exception(f"DriverPackager: Building {c4zName} failed.")

        # CLEANUP ANY TEMPORARY FILES.
        self.CleanupTmpFile(root_directory_path)

        # BUILD ANY C4I DRIVERS.
        is_c4i_driver: bool = (driver_type == "c4i")
        if is_c4i_driver:
            # REMOVE THE .C4I THAT WAS GENERATED AS IT IS A ZIPPED UP .C4I.
            # It will be replaced with an updated file created later below.
            os.remove(os.path.join(self.destination_directory_path, c4zName))

            # FIND THE TEMPORARY DIRECTORY CONTAINING THE NEEDED DRIVER.XML AND DRIVER.LUA.SQUISHED.
            source_driver_temporary_directory_path = None
            root_temporary_directory_path = tempfile.gettempdir()
            temporary_directories = next(os.walk(root_temporary_directory_path))[1]
            for temporary_directory_name in temporary_directories:
                is_squished_lua_directory: bool = str(temporary_directory_name).startswith("Squished_Lua_")
                if is_squished_lua_directory:
                    source_driver_temporary_directory_path  = os.path.join(root_temporary_directory_path, temporary_directory_name)

            # If source path wasn't found, then the temp directory was not created because encryption was detected in the driver.xml (see build_c4z.py).
            source_driver_temporary_directory_found: bool = source_driver_temporary_directory_path is not None
            if not source_driver_temporary_directory_found:
                raise Exception("Encryption was detected in the driver.xml.  When building drivers of type 'c4i', encryption must be disabled.  Please remove the attribute and value of encryption='2' from the <script> element in the driver.xml")

            # UPDATE THE DRIVER.XML.
            driver_xml_filepath: str = os.path.join(self.source_directory_path, "driver.xml")
            self.UpdateDriverXml(driver_xml_filepath)

            # REMOVE ANY <script> SECTIONS IN THE DRIVER.XML.
            xmlTree = etree.parse(driver_xml_filepath)
            xmlRootDriver = xmlTree.getroot()
            script = xmlRootDriver.findall('./config/script')
            script_element_exists: bool = script is not None
            if script_element_exists:
                config = xmlRootDriver.find('config')
                for script in config.findall('script'):
                    config.remove(script)

            temporary_driver_2_xml_filepath: str = os.path.join(source_driver_temporary_directory_path, "driver2.xml")
            xmlTree.write(temporary_driver_2_xml_filepath)

            # GET THE SQUISHED LUA FILE CONTENTS.
            squished_lua_driver_filepath: str = os.path.join(self.source_directory_path, "driver.lua.squished")
            squished_lua_driver_file = codecs.open(squished_lua_driver_filepath, 'r', encoding='utf-8')
            squished_lua_driver_file_lines = squished_lua_driver_file.readlines()
            squished_lua_driver_file.close()

            # ADD THE SQUISHED LUA TO THE <script> SECTION OF THE DRIVER.
            # It must be wrapped in <CDATA> tags.
            document = etree.parse(temporary_driver_2_xml_filepath)
            parent = document.find('config')
            child = etree.SubElement(parent, 'script')
            child.text = etree.CDATA(''.join(squished_lua_driver_file_lines))

            # WRITE OUT THE FINAL C4I DOCUMENT.
            destination_c4i_filepath: str = os.path.join(self.destination_directory_path, c4zName)
            document.write(destination_c4i_filepath, pretty_print=True)

        else:
            # UNZIP THE C4Z DRIVER IN THE DESTINATION DIRECTORY IF ENABLED.
            if self.unzip:
                driver_destination_filepath = os.path.join(self.destination_directory_path, c4zName)
                driver_destination_filepath_without_extension = os.path.splitext(driver_destination_filepath)[0]

                # ENSURE A CLEAN DIRECTORY EXISTS FOR EXTRACTING THE DRIVER.
                driver_extraction_directory_exists: bool = os.path.exists(driver_destination_filepath_without_extension)
                if driver_extraction_directory_exists:
                    shutil.rmtree(driver_destination_filepath_without_extension)
                    
                # EXTRACT THE DRIVER TO THE DESTINATION DIRECTORY.
                with zipfile.ZipFile(driver_destination_filepath, "r") as driver_zip_file:
                    driver_zip_file.extractall(driver_destination_filepath_without_extension)

        # EXECUTE ANY POSTPACKAGING COMMANDS.
        postpackage_command_xml_elements = xmlRoot.find('PostpackageCommands')
        postpackage_commands_exist: bool = postpackage_command_xml_elements is not None
        if postpackage_commands_exist:
            # EXECUTE EACH POSTPACKAGING COMMAND.
            for postpackage_command_xml_element in postpackage_command_xml_elements:
                # VERIFY THE COMMAND XML IS VALID.
                print(postpackage_command_xml_element.tag, postpackage_command_xml_element.text)
                is_valid_postpackage_command_xml: bool = (postpackage_command_xml_element.tag == 'PostpackageCommand')
                if is_valid_postpackage_command_xml:
                    self.Log(f"Invalid XML: Found tag '{postpackage_command_xml_element.tag}', should be 'PostpackageCommand'")
                    continue

                # EXCEUTE THE POSTPACKAGING COMMAND.
                # Commands should use the correct path separator for the current OS.
                postpackage_command: str = postpackage_command_xml_element.text.replace("\\", os.path.sep)
                postpackage_command = postpackage_command.replace("/", os.path.sep)
                SUCCESS_RETURN_CODE: int = 0
                postpackage_command_return_code: int = os.system(postpackage_command)
                postpackage_command_succeeded: bool = (postpackage_command_return_code == SUCCESS_RETURN_CODE)
                if postpackage_command_succeeded:
                    print("Failed to execute postpackage command.")

    ## Updates the driver XML.
    ## \param[in]   driver_xml_filepath - Path to the driver XML file to update.
    ## \throws  Exception - If an error occurs.
    def UpdateDriverXml(self, driver_xml_filepath: str):
        try:
            # GET THE ROOT ELEMENT OF THE DRIVER XML FILE.
            driver_xml_tree = etree.parse(driver_xml_filepath)
            driver_xml_root_element = driver_xml_tree.getroot()

            # UPDATE THE MODIFIED DATE IF APPLICABLE.
            if self.update_modified:
                # ENSURE THE DATE MODIFIED ELEMENT EXISTS.
                date_modified_xml_element = driver_xml_root_element.find("modified")
                date_modified_xml_element_exists: bool = dateModified is not None
                if date_modified_xml_element_exists:
                    raise Exception("<modified> tag not found")

                # UPDATE THE DATE MODIFIED ELEMENT WITH THE CURRENT TIMESTAMP.
                timestamp = datetime.datetime.now()
                timestamp = timestamp.strftime("%m/%d/%Y %I:%M %p")
                date_modified_xml_element.text = timestamp
                self.Log(f"Build timestamp {timestamp}")

            # UPDATE THE DRIVER VERSION IF APPLICABLE.
            if self.driver_version:
                # ENSURE THE DRIVER VERSION ELEMENT EXISTS.
                driver_version_xml_element = driver_xml_root_element.find("version")
                driver_version_xml_element_exists: bool = driver_version_xml_element is not None
                if not driver_version_xml_element_exists:
                    raise Exception("<version> tag not found")

                # MAKE SURE THERE IS AN OLD VERSION TO UPDATE.
                old_version = driverVersion.text
                old_version_exists: bool = old_version is not None
                if not old_version_exists:
                    raise Exception("empty <version> tag")

                # UPDATE THE DRIVER VERSION IN TH XML.
                driver_version_xml_element.text = self.driver_version

            # WRITE THE UPDATED XML.
            driver_xml_tree.write(self.bytes_io, encoding='UTF-8', xml_declaration=False)
        except Exception as exception:
            self.Log(exception)
            raise Exception("Unable to update driver.xml")

    ## Builds a driver according to how this packager was configured.
    ## \return  A return code for driver packaging (0 = success, other values = failure).
    def DriverPackager(self) -> int:
        # BUILD THE DRIVER FROM A MANIFEST IF ONE WAS SPECIFIED.
        manifest_explicitly_specified: bool = self.manifest_xml_filename is not None
        if manifest_explicitly_specified:
            self.Log(f"Building driver from manifest {self.manifest_xml_filename}...")
            manifest_xml_filepath: str = os.path.join(self.source_directory_path, self.manifest_xml_filename)
            return_code: int = self.CreateFromManifest(manifest_xml_filepath)
            return return_code

        # SEARCH FOR A MANIFEST IN THE SOURCE DIRECTORY (.c4zproj).
        manifest_path_from_source_directory: Optional[str] = None
        source_directory_entries: list[str] = os.listdir(self.source_directory_path)
        for filename in source_directory_entries:
            # CHECK IF THE FILE IS FOR A C4Z PROJECT FILE.
            filename_without_extension, file_extension = os.path.splitext(filename)
            is_c4z_project_file: bool = (file_extension == ".c4zproj")
            if is_c4z_project_file:
                # CHECK IF THE PARENT DIRECTORY PATH MATCHES THE PROJECT NAME.
                source_directory_parent_path, source_directory_name = os.path.split(self.source_directory_path)
                source_directory_name_matches_project_name: bool = (source_directory_name == filename_without_extension)
                if source_directory_name_matches_project_name:
                    # USE THIS PROJECT FILE AS THE MANIFEST.
                    manifest_path_from_source_directory = os.path.join(self.source_directory_path, filename)
                    break

        # BUILD THE C4Z DRIVER FROM THE PROJECT MANIFEST IF FOUND.
        if manifest_path_from_source_directory:
            self.Log(f"Building driver from manifest {filename}...")
            return_code: int = self.CreateFromManifest(manifest_path_from_source_directory)
            return return_code

        # BUILD THE C4Z DRIVER FROM ALL FILES IN THE SOURCE DIRECTORY.
        # With no manifest found, all files in source source directory are assumed to be for the driver,
        # with the driver's name matching that of the source directory.
        #
        # CONFIGURE LUA SQUISHING.
        # Lua squishing to a single file can only occur if an appropriate config file exists.
        squish_lua: bool = False
        lua_squish_config_filepath: str = self.source_directory_path + os.path.sep + "squishy"
        lua_squish_config_file_exists: bool = os.path.isfile(lua_squish_config_filepath)
        if lua_squish_config_file_exists:
            squish_lua = True
        c4z.setSquishLua(squish_lua)

        # PROVIDE VISIBILITY INTO BUILDING THE DRIVER FROM A DIRECTORY.
        source_directory_absolute_path: str = os.path.abspath(self.source_directory_path)
        self.Log(f"Building driver from directory {source_directory_absolute_path}...")

        # DETERMINE C4Z FILENAMES.
        c4z_filename: str = os.path.basename(self.source_directory_path) + ".c4z"
        c4z_script_filename: str = self.GetEncryptFilename(
            os.path.join(self.source_directory_path, "driver.xml"))

        # SQUISH LUA FILES INTO A SINGLE FILE IF APPLICABLE.
        if squish_lua:
            self.Squish(self.source_directory_path)

        # COMPRESS THE C4Z DRIVER.
        destination_c4z_filepath: str = os.path.join(self.destination_directory_path, c4z_filename)
        c4z.compress(
            destination_c4z_filepath,
            self.source_directory_path,
            c4z_script_filename,
            xmlByteOverride=self.bytes_io.getvalue())

        # INDICATE THAT CREATING THE DRIVER SUCCEEDED.
        SUCCESS_RETURN_CODE: int = 0
        return SUCCESS_RETURN_CODE


    ## Logs a line to the console (if verbose output is enabled).
    ## \param[in]   line - The line to log.  Typically expected to be a string
    #       but may be any object (like an exception) convertible to a string.
    def Log(self, line: Any):
        # LOG ONLY IF VERBOSE OUTPUT IS ENABLED.
        if self.verbose:
            # A timestamp provides additional context to the message.
            log_message_timestamp: str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
            print(f"{log_message_timestamp}: {line}")
            # Flushing ensures the message will be printed immediately.
            sys.stdout.flush()


## Creates a driver packager based on command line arguments.
## \return  An appropriately configured driver packager.
def CreateDriverPackagerFromCommandLineArguments() -> DriverPackager:#
    # PARSE COMMAND LINE ARGUMENTS.
    command_line_argument_parser = argparse.ArgumentParser()
    command_line_argument_parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose.")
    command_line_argument_parser.add_argument("source_directory_path",
                        help="Directory where c4z source files are located.")
    command_line_argument_parser.add_argument("destination_directory_path",
                        help="Directory where c4z files are placed.")
    command_line_argument_parser.add_argument("manifest_xml_filename",
                        help="[optional] Filename of manifest xml file.",
                        nargs='?')
    command_line_argument_parser.add_argument("-u", "--unzip", action="store_true",
                        help="[optional] Unzip the c4z in the target location.")
    command_line_argument_parser.add_argument("-ae", "--allowexecute", action="store_true",
                        help="[optional] Allow Execute in Lua Command window.")
    command_line_argument_parser.add_argument("--update-modified", action="store_true",
                        help="[optional] Update driver modified date.")
    command_line_argument_parser.add_argument("--driver-version", nargs=1,
                        help="[optional] Update driver version to next argument.")
    command_line_arguments: argparse.Namespace = command_line_argument_parser.parse_args()

    # RETURN A DRIVER PACKAGER CONFIGURED ACCORDING TO THE COMMAND LINE ARGUMENTS.
    driver_packager = DriverPackager(command_line_arguments)
    return driver_packager


# RUN THE DRIVER PACKAGER IF THIS FILE IS BEING RUN DIRECTLY.
if __name__ == "__main__":
    driver_packager: DriverPackager = CreateDriverPackagerFromCommandLineArguments()
    return_code: int = driver_packager.DriverPackager()
    sys.exit(return_code)
