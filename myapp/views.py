import google.generativeai as genai

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Feature
from .models import Alert
from django.http import JsonResponse
from django.db.models import Count
from .forms import CreateUserForm
from .forms import ProfileForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from sqlalchemy import create_engine, text
# Create your views here.


@login_required(login_url='login')
def index(request):
    alerts = Alert.objects.all()
    
    #********************************************************************************************** 24 heurs only ************************************************************************************************
    now = timezone.now()

    alerts = alerts.filter(time__gte=now - timedelta(days=1))

    # Count alerts by severity and status
    critical = alerts.filter(severity='Critical').count()
    medium = alerts.filter(severity='Medium').count()
    pending_status = alerts.filter(status='Pending').count()
    resolved_status = alerts.filter(status='Resolved').count()
    error_status = alerts.filter(status='Error').count()

    # Top 5 Targets (using the 'computer' field)
    top_targets = (
        Alert.objects.values("computer")
        .annotate(incident_count=Count("alert_id"))
        .order_by("-incident_count")[:5]
    )

    # Top 5 Attackers (using the 'source' field)
    top_attackers = (
        Alert.objects.values("source")
        .annotate(attack_count=Count("alert_id"))
        .order_by("-attack_count")[:5]
    )

    # Classification of attacks by description keywords
    attack_patterns = {
        "Brute Force": ["brute force", "failed login", "multiple login attempts"],
        "Malware": ["malware", "trojan", "ransomware", "VirusTotal"],
        "DDoS": ["denial of service", "ddos", "botnet"],
        "Port Scan": ["port scan", "reconnaissance"],
        "SQL Injection": ["sql injection", "database error", "sql syntax"],
    }

    # Top 5 Attacks by type
    attack_counts = {}
    for attack_type, keywords in attack_patterns.items():
        attack_counts[attack_type] = (
            Alert.objects.filter(
                description__iregex="|".join(keywords)  # Case-insensitive search
            ).count()
        )

    top_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    context = {
        'critical': critical,
        'medium': medium,
        'pending_status': pending_status,
        'resolved_status': resolved_status,
        'error_status': error_status,
        'top_targets': top_targets,
        'top_attackers': top_attackers,
        'top_attacks': top_attacks,
    }
    return render(request, 'index.html', context)




from django.utils import timezone
from datetime import timedelta, datetime
from django.db.models import Q
# View to render the main page with filter controls
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils.html import escape # For security
from django.template.loader import render_to_string

@login_required(login_url='login')
def alerts_dashboard(request):
    return render(request, 'wazuh.html')

# View to handle AJAX requests and return filtered alert data (JSON)
def fetch_filtered_alerts(request):
    # --- Filtering Logic (remains the same) ---
    queryset = Alert.objects.all()
    start_time_str = request.GET.get('start_time', '').strip()
    end_time_str = request.GET.get('end_time', '').strip()
    time_filter = request.GET.get('time_filter', '').strip()
    search = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()

    now = timezone.now()
    if time_filter == "24h": queryset = queryset.filter(time__gte=now - timedelta(days=1))
    elif time_filter == "7d": queryset = queryset.filter(time__gte=now - timedelta(days=7))
    elif time_filter == "30d": queryset = queryset.filter(time__gte=now - timedelta(days=30))

    try:
        if start_time_str: queryset = queryset.filter(time__gte=datetime.fromisoformat(start_time_str))
    except ValueError: pass
    try:
        if end_time_str: queryset = queryset.filter(time__lte=datetime.fromisoformat(end_time_str))
    except ValueError: pass

    if search: queryset = queryset.filter(Q(description__icontains=search) | Q(computer__icontains=search))
    if status_filter and status_filter in ['resolved', 'pending', 'error']: queryset = queryset.filter(status=status_filter)
    if severity_filter and severity_filter in ['Critical', 'Medium', 'Low']: queryset = queryset.filter(severity=severity_filter)

    queryset = queryset.order_by('-time')
    # --- End Filtering Logic ---


    # --- Pagination Logic ---
    page_number = request.GET.get('page', 1)
    items_per_page = 10 # Or get from request: request.GET.get('per_page', 10)

    paginator = Paginator(queryset, items_per_page)

    try:
        alerts_page = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        alerts_page = paginator.page(1)
        page_number = 1
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        alerts_page = paginator.page(paginator.num_pages)
        page_number = paginator.num_pages

    # --- End Pagination Logic ---


    # --- Rendering HTML Parts ---

    # Render table rows using the template snippet approach (Recommended)
    # Ensure you have '_alert_rows.html' as shown in previous answers
    # Pass the 'alerts_page' object which contains the items for the current page
    # html_rows = render_to_string('_alert_rows.html', {'alerts': alerts_page})

    # OR: Render table rows directly (Less maintainable, but works)
    html_rows = ""
    if alerts_page.object_list: # Use object_list from the page object
        for alert in alerts_page.object_list:
            status_class = ""
            if alert.status == 'resolved': status_class = 'resolved'
            elif alert.status == 'pending': status_class = 'open'
            elif alert.status == 'error': status_class = 'on-hold'
            formatted_time = alert.time.strftime('%Y-%m-%d %H:%M:%S') if alert.time else 'N/A'
            safe_severity = escape(alert.severity)
            safe_computer = escape(alert.computer)
            safe_description = escape(alert.description)
            safe_status = escape(alert.status)
            safe_id=escape(alert.alert_id)
            ss = f'onclick="window.location.href=\'/incident?id={safe_id}\'"'
            html_rows += f"""
            <tr {ss}>
                <td>{formatted_time}</td>
                <td>{safe_severity}</td>
                <td>{safe_computer}</td>
                <td>{safe_description}</td>
                <td><span class="status {status_class}">{safe_status}</span></td>
            </tr>
            """
    else:
         html_rows = f"<tr><td colspan='5'>No alerts found matching criteria.</td></tr>" # Match colspan

    # Render pagination controls using a new snippet
    pagination_html = render_to_string('_pagination_controls.html', {'alerts_page': alerts_page})

    # --- End Rendering HTML Parts ---

    # Return JSON
    return JsonResponse({
        'html_rows': html_rows,
        'pagination_html': pagination_html,
        'current_page': int(page_number), # Send current page back if needed
        'total_pages': paginator.num_pages # Send total pages back if needed
    })




#******************************************************* CHATBOT ***************************************************************************




from urllib.parse import quote_plus
from dotenv import load_dotenv
import os

load_dotenv()

db_user = os.getenv("DB_USER")
db_password_raw = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")
api_key = os.getenv("GEMINI_API_KEY")

db_password_encoded = quote_plus(db_password_raw)

# Configure your Gemini API key
genai.configure(api_key=os.getenv("GEMINI_API_KEY")) # Replace with your actual API key

model_name = 'models/gemini-2.5-pro-exp-03-25' # or 'models/gemini-1.5-flash', or 'models/gemini-1.5-flash-8b', or a gemini 2.0 model.

""" python3 model-test.py Model Name: models/chat-bison-001 Model Name: models/text-bison-001 Model Name: models/embedding-gecko-001 Model Name: models/gemini-1.0-pro-vision-latest Model Name: models/gemini-pro-vision Model Name: models/gemini-1.5-pro-latest Model Name: models/gemini-1.5-pro-001 Model Name: models/gemini-1.5-pro-002 Model Name: models/gemini-1.5-pro Model Name: models/gemini-1.5-flash-latest Model Name: models/gemini-1.5-flash-001 Model Name: models/gemini-1.5-flash-001-tuning Model Name: models/gemini-1.5-flash Model Name: models/gemini-1.5-flash-002 Model Name: models/gemini-1.5-flash-8b Model Name: models/gemini-1.5-flash-8b-001 Model Name: models/gemini-1.5-flash-8b-latest Model Name: models/gemini-1.5-flash-8b-exp-0827 Model Name: models/gemini-1.5-flash-8b-exp-0924 Model Name: models/gemini-2.5-pro-exp-03-25 Model Name: models/gemini-2.5-pro-preview-03-25 Model Name: models/gemini-2.0-flash-exp Model Name: models/gemini-2.0-flash Model Name: models/gemini-2.0-flash-001 Model Name: models/gemini-2.0-flash-exp-image-generation Model Name: models/gemini-2.0-flash-lite-001 Model Name: models/gemini-2.0-flash-lite Model Name: models/gemini-2.0-flash-lite-preview-02-05 Model Name: models/gemini-2.0-flash-lite-preview Model Name: models/gemini-2.0-pro-exp Model Name: models/gemini-2.0-pro-exp-02-05 Model Name: models/gemini-exp-1206 Model Name: models/gemini-2.0-flash-thinking-exp-01-21 Model Name: models/gemini-2.0-flash-thinking-exp Model Name: models/gemini-2.0-flash-thinking-exp-1219 Model Name: models/learnlm-1.5-pro-experimental Model Name: models/gemma-3-1b-it Model Name: models/gemma-3-4b-it Model Name: models/gemma-3-12b-it Model Name: models/gemma-3-27b-it Model Name: models/embedding-001 Model Name: models/text-embedding-004 Model Name: models/gemini-embedding-exp-03-07 Model Name: models/gemini-embedding-exp Model Name: models/aqa Model Name: models/imagen-3.0-generate-002 """ 
model = genai.GenerativeModel(model_name)



# URL-encode the password
db_password_encoded = quote_plus(db_password_raw)

# Construct the connection string with the encoded password
connection_string = f"mysql+pymysql://{db_user}:{db_password_encoded}@{db_host}/{db_name}"

# Create the engine
engine = create_engine(connection_string)



def chatbot(request):
    query = request.GET.get("query", "").lower()

    table_structure = """
    Table: alert
        Columns:
        alert_id (INT, AUTO_INCREMENT, PRIMARY KEY)
        time (DATETIME(6), NOT NULL)
        source (VARCHAR(50), NOT NULL)
        severity (VARCHAR(8), NOT NULL)
        computer (VARCHAR(255), NOT NULL)
        account_name (VARCHAR(255), NULLABLE)
        description (LONGTEXT, NOT NULL)
        status (VARCHAR(25), NOT NULL)
        full_alert (LONGTEXT, NOT NULL)
        full_response (LONGTEXT, NOT NULL)
        response_desc (LONGTEXT, NOT NULL)
        responder (LONGTEXT, NOT NULL)
    """

    prompt = f"""
    {table_structure}
    Convert this natural language question into a MySQL query for the 'alert' table, considering the table structure above: {query}.
    Only return the SQL query without explanation. If the question does not require a SQL query, return 'NON_SQL'
    """
    
    try:
        response = model.generate_content(prompt)
        sql_query = response.text.strip()
        sql_query = sql_query.replace("```sql", "").replace("```", "").strip()

        if sql_query.upper() != "NON_SQL":
            if "SELECT" in sql_query.upper():
                try:
                    with engine.connect() as connection:
                        result = connection.execute(text(sql_query))
                        rows = result.fetchall()
                        if len(rows) == 1 and len(rows[0]) == 1:
                            return JsonResponse({"response": str(rows[0][0])})
                        elif len(rows) >= 0:
                            formatted_rows = [str(row) for row in rows]
                            return JsonResponse({"response": ", ".join(formatted_rows)})
                        else :
                            return JsonResponse({"response": "No Results"})

                except Exception as e:
                    return JsonResponse({"response": f"SQL Error: {str(e)}"})
            else:
                return JsonResponse({"response": "Invalid SQL Query"})
        else:
            gemini_prompt = f"You are a cybersecurity assistant. Answer this: {query}"
            gemini_response = model.generate_content(gemini_prompt)
            return JsonResponse({"response": gemini_response.text})

    except Exception as e:
        return JsonResponse({"response": f"Gemini Error: {str(e)}"})



@login_required(login_url='login')    
def chat_page(request):
    return render(request, 'chatbot.html')



def loginPage(request):
    if request.user.is_authenticated:
        return redirect("/")
    else:
        if request.method == 'POST' :
            username = request.POST.get('username')
            password = request.POST.get('password')

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect("/")
            else:
                messages.info(request, 'Username OR password is incorrect')

    return render(request, 'login.html')

def registerPage(request): 
    if request.user.is_authenticated:
        return redirect("/")
    else: 
        form = CreateUserForm()
        if request.method == 'POST':
            form = CreateUserForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Account was created')
                return redirect('login')
            else:
                errors = form.errors.as_text()  # Récupérer les erreurs en texte
                messages.error(request, f'There are errors in your input: {errors}')
    return render(request, 'register.html', {'form': form})


def logoutUser(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login')
def profile(request):
    if request.method == "POST":
        user = request.user
        username = request.POST.get("username")
        email = request.POST.get("email")

        # Update username and email
        user.username = username
        user.email = email
        user.save()

        # Handle password change
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if old_password and new_password and new_password == confirm_password:
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)  # Keep user logged in after password change
            else:
                return render(request, "profile.html", {"error": "Incorrect current password."})

        return redirect("profile")

    return render(request, "profile.html")




#********************************************************************** Incident  *************************************************************************************

@login_required(login_url='login')
def incident(request):
    id = request.GET.get("id")
    alerts = Alert.objects.all()

    # Compter les alertes selon leur criticité
    for a in alerts : 
        if ( a.alert_id==int(id) ) :
            full_response = a.full_response
            full_alert  = a.full_alert
            status=a.status
            response_desc=a.response_desc
            responder_name=a.responder
            time=a.time
            """
    if extract_public_ips(full_alert) : 
        checkipdb(extract_public_ips(full_alert))
        """
    return render(request, "incident.html",{'id':id,'time':time,'falert':full_alert,'frepp':full_response,'status':status,'response_desc': response_desc,'responder_name':responder_name})



#***************************************  IP EXTRACTOR  *****************************************************************
"""
import re
import ipaddress

def extract_public_ips(text):
    ip_candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    public_ips = []

    for ip in ip_candidates:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private:
                public_ips.append(ip)
        except ValueError:
            continue  # skip invalid IPs
    return public_ips


#*******************************************   Abuse IPDB  *******************************************************
import requests
def checkipdb(theip):
    url = "https://api.abuseipdb.com/api/v2/check"

    querystring = {
        "ipAddress": theip[0],
        "maxAgeInDays": "90"
    }

    headers = {
        "Accept": "application/json",
        "Key": "e54da243eb711adbd5b8c8b315ad979d2e34fd933e5275863dac542fe9b554fed7af8104eb485bdc"
    }

    response = requests.get(url, headers=headers, params=querystring)

    print("Status Code:", response.status_code)

    if response.status_code == 200:
        data = response.json()
        print(data)
    else:
        print("error")
        print(response.text)

"""


import requests
import json
from django.http import StreamingHttpResponse, JsonResponse, HttpResponseBadRequest
# --- Configuration ---
OLLAMA_API_URL = "http://127.0.0.1:11434/api/chat" # Make sure this is correct

OLLAMA_MODEL = "mistral" # Or your preferred model
REQUEST_TIMEOUT = 120 # Timeout for Ollama request in seconds

 # Ensure this view only accepts POST requests
# @csrf_exempt # Quick way for testing API, REMOVE in production or handle CSRF properly
             # See note below on CSRF handling

def analyze_with_ai(request):
    """
    Receives text via POST, sends it to Ollama, and streams the response.

    """
    try:
        data = json.loads(request.body)
        text_to_analyze = data.get('text')
        section = data.get('section', 'unknown') # Optional: know which section was clicked

        if not text_to_analyze:
            return JsonResponse({'error': 'No text provided'}, status=400)

        print(f"Received text for AI analysis (section: {section}): {text_to_analyze[:100]}...") # Log received text

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
         return JsonResponse({'error': f'Error processing request data: {str(e)}'}, status=400)

    # Define the generator function for streaming
    def stream_ollama_response(prompt_text):
        prompt_text = "so you have this json text analys it and explaine whats happing and whats i can do to stop the attack ore resolvit if its anrady responded explaine what heppend only "+ prompt_text 
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt_text}],
            "stream": True # Ensure Ollama knows we want streaming
        }
        headers = {'Content-Type': 'application/json'}

        try:
            print(f"Sending request to Ollama: {OLLAMA_API_URL}")
            # Use requests with stream=True
            response = requests.post(
                OLLAMA_API_URL,
                headers=headers,
                json=payload,
                stream=True,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            print("Streaming response from Ollama...")
            for line in response.iter_lines(decode_unicode=True):
                if line:
                    try:
                        json_data = json.loads(line)
                        if json_data.get("done") == True:
                            print("Ollama stream finished.")
                            break # Stop when Ollama signals completion

                        message_part = json_data.get("message", {}).get("content", "")
                        if message_part:
                            yield message_part # Yield the content part

                    except json.JSONDecodeError:
                        print(f"Warning: Failed to parse line from Ollama: {line}")
                        # Decide if you want to yield an error message or just skip
                        # yield f"[Error parsing chunk: {line}]"
                    except Exception as e:
                        print(f"Error processing Ollama stream chunk: {e}")
                        yield f"[Stream Processing Error: {e}]"


        except requests.exceptions.ConnectionError as e:
             print(f"Error connecting to Ollama: {e}")
             yield f"[Error: Could not connect to Ollama at {OLLAMA_API_URL}. Is it running?]"
        except requests.exceptions.Timeout:
            print(f"Error: Request to Ollama timed out after {REQUEST_TIMEOUT} seconds.")
            yield f"[Error: Ollama request timed out.]"
        except requests.exceptions.RequestException as e:
            print(f"Error during request to Ollama: {e}")
            error_detail = response.text if 'response' in locals() else str(e)
            yield f"[Error: Ollama API request failed. Status: {getattr(response, 'status_code', 'N/A')}. Details: {error_detail[:200]}]"
        except Exception as e:
            print(f"Unexpected error during Ollama interaction: {e}")
            yield f"[Unexpected Server Error: {e}]"

    # Create the StreamingHttpResponse using the generator
    response = StreamingHttpResponse(
        stream_ollama_response(text_to_analyze),
        content_type='text/plain' # Stream plain text chunks
        # Use 'text/event-stream' if you want to implement Server-Sent Events fully
    )
    return response

# --- Add your other views here (like the one rendering the detail page) ---
# Example: def alert_detail_view(request, alert_id): ...






from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json


@csrf_exempt  # Remove this if using CSRF token in the frontend
def resolve_alert(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            aalert_id = data.get("alert_id")
            username = data.get("username")
            response_description = data.get("response_description")
            print(response_description)
            # Ensure all required fields are provided
            if not all([aalert_id, username, response_description]):
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Update the alert if it exists
          
            # Update alert in the database
            from .models import Alert  # Import your model
            alert = Alert.objects.get(alert_id=aalert_id)
            alert.responder = username
            alert.response_desc = response_description
            alert.status = "resolved"   # Assuming you have a field for resolution status
            alert.save()

            return JsonResponse({"success": True, "message": "Alert resolved successfully."})
        
        except Alert.DoesNotExist:
            return JsonResponse({"success": False, "error": "Alert not found."}, status=404)
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)
