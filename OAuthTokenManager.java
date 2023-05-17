package com.bkw.oauth;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;

import com.fasterxml.jackson.databind.ObjectMapper;

public class OAuthTokenManager {
	private static OAuthTokenManager singleton = null;
	private String oAuthToken = null;
	private String oAuthRefreshToken = null;
	private Date created;
	private Date lastUsed;
	private long idleTimeout;
	private long sessionExpires;
	private String baseURL;
	private String username;
	private String password;
	private String clientID = null;
	private String domainCode = null;
	
	public static OAuthTokenManager getInstance(String baseURL,String username,String password,String domainCode) throws Exception {
		if(singleton==null) singleton=new OAuthTokenManager();
		singleton.SetData(baseURL, username, password, domainCode);
		return singleton;
	}
	
	private void getSecurityControlSettings() throws Exception {
	    HttpClient client = new DefaultHttpClient();
	    String entityCode = null;
	    String oauthToken;
	    String authorization;
	      
	    authorization = "Basic "+Base64.getEncoder().encodeToString(new String(username+":"+password).getBytes());

/*** This is not needed, since the security control is system wide and not domain specific 
	    // Retrieve domain's primary entity
	    HttpGet apiRequest = new HttpGet(baseURL+"/api/qracore/browses?browseId=urn:browse:bebrowse:com.qad.erp.base.domainV3s&filter=domainV3.domainContext%2Ceq%2C"+domainCode+"%2Cliteral");
	    apiRequest.addHeader("Content-Type", "application/json");
	    apiRequest.addHeader("Authorization", authorization);

	    HttpResponse apiResponse = client.execute(apiRequest);
	    ByteArrayOutputStream stream = new ByteArrayOutputStream();
	    apiResponse.getEntity().writeTo(stream);
	    stream.close();
	    String body = stream.toString();
	    int statusCode = apiResponse.getStatusLine().getStatusCode();
	    
	    if(statusCode==200) {
		  ObjectMapper jsonMapper = new ObjectMapper();
		  LinkedHashMap map = (LinkedHashMap)jsonMapper.readValue(body, Object.class);
		  ArrayList data=(ArrayList)map.get("data");
		  LinkedHashMap record=(LinkedHashMap)data.get(0);
		  entityCode=(String)record.get("domainV3.entityContext");
	    }
	    
	    if(entityCode==null) {
	    	throw new Exception("Unable to retrieve entity code for domain: "+domainCode);
	    }
***/

	    // Retrieve security control settings for given domain
	    HttpGet apiRequest = new HttpGet(baseURL+"/api/qracore/securityControl");
	    apiRequest.addHeader("Content-Type", "application/json");
	    apiRequest.addHeader("Authorization", authorization);
	      
	    HttpResponse apiResponse = client.execute(apiRequest);
	    ByteArrayOutputStream stream = new ByteArrayOutputStream();
	    apiResponse.getEntity().writeTo(stream);
	    stream.close();
	    String body = stream.toString();
	    int statusCode = apiResponse.getStatusLine().getStatusCode();
		
	    if(statusCode==200) {
		  ObjectMapper jsonMapper = new ObjectMapper();
		  LinkedHashMap map = (LinkedHashMap)jsonMapper.readValue(body, Object.class);
		  LinkedHashMap record=(LinkedHashMap)map.get("data");
		  ArrayList data=(ArrayList)record.get("securityControls");
		  record=(LinkedHashMap)data.get(0);
		  clientID=(String)record.get("clientId");
		  // Convert session expiration and timeout from minutes to milliseconds (60s/min x 1000ms/s)
		  sessionExpires=((Integer)record.get("sessionLength")).intValue()*60000;
		  idleTimeout=((Integer)record.get("timeoutMinutes")).intValue()*60000;
	    } else {
	    	throw new Exception("Unable to retrieve security control settings for domain:"+domainCode);
	    }
	    
	}
	
	private void SetData(String baseURL,String username,String password,String domainCode) throws Exception {
		boolean switchDomain=(this.domainCode==null);
		this.baseURL=baseURL;
		this.username=username;
		this.password=password;
		this.domainCode=domainCode;
		
		// TBD: When to reload the security control settings?
		if(switchDomain) {
			getSecurityControlSettings();
			created=null;
			lastUsed=null;
		}
	}
	
	private boolean isNullOrEmpty(String value,boolean checkEmpty) {
		boolean result=(value==null);
		if(result==false && checkEmpty) result=(value.trim().equals(""));
		return result;
	}
	
	protected String createOAuthToken() throws Exception {
		if(isNullOrEmpty(baseURL,true)) {
			throw new Exception("Required base URL is not defined");
		}
		if(isNullOrEmpty(username,true)) {
			throw new Exception("Required user name is not defined");
		}
		if(isNullOrEmpty(password,false)) {
			throw new Exception("Required password is not defined");
		}
		if(isNullOrEmpty(clientID,true)) {
			throw new Exception("Required client ID is not defined");
		}
		if(isNullOrEmpty(domainCode,true)) {
			throw new Exception("Required domain code is not defined");
		}
		
		HttpClient client = new DefaultHttpClient();
		HttpPost apiRequest = new HttpPost(baseURL+"/oauth/token");
		apiRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
		  
		String payload = "client_id="+clientID+"&grant_type=password"+"&username="+username+"&password="+password;
		StringEntity params = new StringEntity(payload);
		apiRequest.setEntity(params);
		
	    HttpResponse apiResponse = client.execute(apiRequest);
	    ByteArrayOutputStream stream = new ByteArrayOutputStream();
	    apiResponse.getEntity().writeTo(stream);
	    stream.close();
	    String body = stream.toString();
	    int statusCode = apiResponse.getStatusLine().getStatusCode();

	    Date now=new Date();
	    if(statusCode==200) {
		    ObjectMapper jsonMapper = new ObjectMapper();
		    LinkedHashMap map = (LinkedHashMap)jsonMapper.readValue(body, Object.class);
		      
		    oAuthToken=(String)map.get("access_token");
		    oAuthRefreshToken=(String)map.get("refresh_token");
		    created=now;
	    } else {
	    	throw new Exception("Unable to retrieve new oauth token");
	    }
	    
	    lastUsed=now;
	      
		return oAuthToken;
	}
	
	public void expireToken() {
		// Set created & lastUsed values to the distant past (1900-01-01)
		created=new Date(0,0,0);
		lastUsed=new Date(0,0,0);
	}
	
	public String getOAuthToken() throws Exception {
		Date now = new Date();
		// Allow for 5 minutes of processing for session expiration and 10 seconds for idle timeout
		if(oAuthToken==null || created==null || lastUsed==null || 
				(now.getTime()+300000-created.getTime())>=sessionExpires || 
				(now.getTime()+10000-lastUsed.getTime())>=idleTimeout) {
			oAuthToken=createOAuthToken();
		}
		lastUsed=now;
		return oAuthToken;
	}
	
	private OAuthTokenManager() {
	}

	public static void main(String[] args) {
		try {
			// Retrieve oauth token for first time
			OAuthTokenManager manager=OAuthTokenManager.getInstance("https://vmlwjaux0001.qad.com/clouderp", "mfg@qad.com", "", "10USA");
			String oAuthToken1=manager.getOAuthToken();
			System.out.println("OAuth Token1: "+oAuthToken1);

			// Re-Retrieve unexpired token, should be same token as previously returned
			String oAuthToken2=manager.getOAuthToken();
			System.out.println("OAuth Token2:same="+oAuthToken2.equals(oAuthToken1)+":"+oAuthToken2);
			
			// Force expiration of token and retrieve a new token, should be different then previously retrieved token
			manager.expireToken();
			String oAuthToken3=manager.getOAuthToken();
			System.out.println("OAuth Token3:different="+!oAuthToken3.equals(oAuthToken1)+":"+oAuthToken3);
		} catch(Exception e) {
			System.out.println("EXCEPTION:"+e);
			e.printStackTrace();

		}
	}

}
