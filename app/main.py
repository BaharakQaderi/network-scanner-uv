from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from app.routers import simple_network
import os

app = FastAPI(
    title="FastAPI Network Scanner",
    description="A FastAPI application for network scanning",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# Include only the network router
app.include_router(simple_network.router, prefix="/network", tags=["network"])



@app.get("/")
async def root():
    """Redirect root to scanner interface"""
    return RedirectResponse(url="/scanner")



@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "fastapi-network-scanner"}


@app.get("/scanner", response_class=HTMLResponse)
async def network_scanner():
    """Serve the network scanner web interface"""
    try:
        static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
        html_file = os.path.join(static_dir, "network_scanner.html")
        
        if os.path.exists(html_file):
            with open(html_file, 'r') as f:
                return f.read()
        else:
            return "<h1>Network Scanner</h1><p>Interface not found</p>"
    except Exception as e:
        return f"<h1>Error</h1><p>Could not load network scanner: {str(e)}</p>"
