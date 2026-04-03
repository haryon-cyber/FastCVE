from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from generic import ApplicationContext
from common.models import SearchOptions, SearchInfoType
from common.search import search_data
from common.util import ensure_db_schema
from web.dependencies import get_app_cntxt
from web.routers.search import router as router_search
from web.models.search import StatusOutput
import os

version = os.getenv("APP_VERSION", "modified")

@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_db_schema()
    yield


app = FastAPI(
    title="FastCVE",
    description="Fast, Rich and API-based search for CVE and more (CPE, CWE, CAPEC)",
    version=version,
    lifespan=lifespan,
)


@app.get("/status", tags=['status'], name="DB status", response_model=StatusOutput)
async def get_status(appctx: ApplicationContext = Depends(get_app_cntxt)) -> StatusOutput:
    """Get the current DB status update"""

    try:
        opts = SearchOptions(searchInfo=SearchInfoType.status)
        result = search_data(appctx, opts)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return result


app.include_router(router_search, prefix="/api")
