class CaseFolderNotFound(Exception):
    def __init__(self, message=None, errors=None):
        if message is None:
            message = "Unable to determine case ID from memory dump path."
        super().__init__(message)
        self.errors = errors


class PreviouslyProcessed(Exception):
    def __init__(self, message=None, errors=None):
        if message is None:
            message = "Previously processed case folder specified.  To re-process, remove 'CASE_PROCESSED_FLAG' file"
        super().__init__(message)
        self.errors = errors


class MemoryImageLoadFailure(Exception):
    def __init__(self, message=None, errors=None):
        if message is None:
            message = "Volatility is unable to load memory image.  Ensure memory format is compatible with Volatility."
        super().__init__(message)
        self.errors = errors


class MemoryImageProfileFailure(Exception):
    def __init__(self, message=None, errors=None):
        if message is None:
            message = "Volatility is unable to determine memory image profile"
        super().__init__(message)
        self.errors = errors


class OverrideConfigFailure(Exception):
    def __init__(self, message=None, errors=None):
        if message is None:
            message = "Failed to process override configuration file."
        super().__init__(message)
        self.errors = errors
