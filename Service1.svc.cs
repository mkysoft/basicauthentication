using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Web;
using System.Text;
using System.Web;

namespace basicauthentication
{
	public class Service1 : IService1
	{
		public string GetData(int value)
		{
			CheckAuthentication();
			return string.Format("You entered: {0}", value);
		}

		private void CheckAuthentication()
		{
			try
			{
				string authToken = null;
				if (HttpContext.Current == null)
				{
					OperationContext context = OperationContext.Current;
					MessageProperties prop = context.IncomingMessageProperties;
					HttpRequestMessageProperty reqMsg = prop["httpRequest"] as HttpRequestMessageProperty;
					if (reqMsg != null)
						authToken = reqMsg.Headers[HttpRequestHeader.Authorization];
				}
				else
				{
					authToken = HttpContext.Current.Request.Headers.Get((int)HttpRequestHeader.Authorization);
				}
				try
				{
					string method = null;
					string username = null;
					string password = null;
					string error = null;
					if (!String.IsNullOrEmpty(authToken))
					{
						string[] tokens = authToken.Split(' ');
						if (tokens.Length == 2)
						{
							method = tokens[0];
							if (!String.IsNullOrEmpty(method) && method.Equals("Basic"))
							{
								if (!String.IsNullOrEmpty(tokens[1]))
								{
									string identifier = Encoding.UTF8.GetString(Convert.FromBase64String(tokens[1]));
									if (!identifier.Contains(":"))
										throw new FaultException("Kullanıcı adı ve şifre formatı Basic Authentication ile uyumlu değil!");

									string[] Identifiers = identifier.Split(':');
									if (Identifiers.Length == 2)
									{
										username = Identifiers[0];
										password = Identifiers[1];
										if (username == "orhan" && password == "gunes")
											return;
										error = "Kullanıcı adı veya şifre uyuşmuyor!";
									}
									else
									{
										error = "Kullanıcı adı ve şifre formatı Basic Authentication ile uyumlu değil!";
									}
								}
								else
								{
									error = "Kullanıcı adı ve şifre formatı Basic Authentication ile uyumlu değil!";
								}
							}
							else
							{
								error = "Authentication yöntemi Basic olmalı!";
							}
						}
						else
						{
							error = "Kullanıcı adı ve şifre formatı Basic Authentication ile uyumlu değil!";
						}
					}
					else
					{
						error = "Authentication bilgisi bulunamadı!";
					}
					if (HttpContext.Current == null)
					{
						HttpResponseMessageProperty responseProperty;
						OperationContext context = OperationContext.Current;
						if (context.OutgoingMessageProperties.ContainsKey(HttpResponseMessageProperty.Name) == false)
						{
							responseProperty = new HttpResponseMessageProperty();
							context.OutgoingMessageProperties.Add(HttpResponseMessageProperty.Name, responseProperty);
						}
						else
						{
							responseProperty = (HttpResponseMessageProperty)context.OutgoingMessageProperties[HttpResponseMessageProperty.Name];
						}
						responseProperty.StatusCode = HttpStatusCode.Unauthorized;
						responseProperty.Headers.Add(HttpResponseHeader.WwwAuthenticate, "Basic realm=\"\"");
					}
					else
					{
						HttpContext.Current.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
						HttpContext.Current.Response.Headers.Add("WWW-Authenticate", "Basic realm=\"\"");
					}
					throw new FaultException(error);
				}
				catch (FaultException)
				{
					throw;
				}
				catch (Exception ex)
				{
					throw new FaultException("Beklenmedik hata: " + ex.Message);
				}
			}
			catch (FaultException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new FaultException("Beklenmedik hata: " + ex.Message);
			}
		}

		public CompositeType GetDataUsingDataContract(CompositeType composite)
		{
			CheckAuthentication();
			if (composite == null)
			{
				throw new ArgumentNullException("composite");
			}
			if (composite.BoolValue)
			{
				composite.StringValue += "Suffix";
			}
			return composite;
		}
	}
}
