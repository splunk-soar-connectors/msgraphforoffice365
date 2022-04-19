**Unreleased**
* Added paginator in On Poll Action [PAPP-24562]
* Fixed a bug in the 'folder' config parameter [PAPP-24524]
* Added a new config parameter 'get_folder_id' to support folder name as well as folder_id in the 'folder' config parameter [PAPP-24565]
* Added validation for the extraction of URL artifacts [PAPP-24517]
* Fixed a bug for the extraction of the URL value from the image src attribute [PAPP-24801]
* Added deduplication logic for handling duplicate emails while ingestion [PAPP-24525]
* Fixed an issue for hash extraction while ingesting email [PAPP-25014]
* Added ability to configure ingestion order [PAPP-24564]
* Bug Fixes in On Poll Action [PAPP-25012, PAPP-25013, PAPP-25015, PAPP-25016, PAPP-24561, PAPP-24563, PAPP-25084, PAPP-25295]
* Fixed On Poll issue where playbooks were triggered twice when an email was an attachment [PAPP-25011]
* Updated app documentation [PAPP-24248]
* Compatibility changes for Python 3 support
