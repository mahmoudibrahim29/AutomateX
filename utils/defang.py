def defang_ioc(ioc: str) -> str:
    ioc = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://")
    ioc = ioc.replace(".", "[.]")
    return ioc
