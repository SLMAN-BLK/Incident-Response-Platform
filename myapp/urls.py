from django.urls import path
from . import views


urlpatterns =[
    path("", views.index, name='index'),
    #path('wazuh/',views.alerts, name='alerts'),
    path('alerts/', views.alerts_dashboard, name='alerts_dashboard'),

    # URL endpoint for the AJAX requests to fetch filtered data
    path('api/fetch-alerts/', views.fetch_filtered_alerts, name='fetch_filtered_alerts_api'),
    path('chatbot',views.chatbot, name='chatbot'),
    path('chat', views.chat_page, name='chat_page'),
    path('login/', views.loginPage, name='login'),
    path('register/', views.registerPage, name='register'),
    path('logout/', views.logoutUser, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('incident/', views.incident, name='incident'),
    
    path('api/analyze-ai/', views.analyze_with_ai, name='analyze_ai_api'), # New API endpoint

    path("api/resolve-alert/", views.resolve_alert, name="resolve_alert"),# response API
     
     
     
    #path('response_api', views.response_api_view, name='response_api'), 


]