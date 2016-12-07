// MIGS payment gateway using Asp.Net MVC5
// Based off https://github.com/mwd-au/MIGS-payment-gateway-MVC5

using MigsPayments.Helpers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Mvc;

namespace MigsPayments.Controllers
{
    public class PaymentController : Controller
    {
        // GET: Payment
        public ActionResult Index()
        {
            var PaymentStatus = "none";

            try
            {
                string hashSecret = ConfigurationManager.AppSettings["MigsSecureHashSecret"];
                var returnsecureHash = Request.QueryString["vpc_SecureHash"];
                var txnResponseCode = Request.QueryString["vpc_TxnResponseCode"];

                // return value
                Dictionary<string, string> data = new Dictionary<string, string>();
                foreach (var key in Request.QueryString)
                {
                    data.Add(key.ToString(), Request.QueryString.GetValues(key.ToString())[0]);
                }

                var newData = data.Where(x => x.Key != "vpc_SecureHash" && x.Key != "vpc_SecureHashType").OrderBy(t => t.Key, new VPCStringComparer()).ToList();

                string shaKey = ConfigurationManager.AppSettings["MigsSecureHashSecret"];
                string shaData = string.Join("&", newData.Select(item => item.Key + "=" + item.Value));

                // create hash
                var securehash = PaymentHelperMethods.CreateSHA256Signature(shaKey, shaData);

                // check returnsecureHash
                if (!string.IsNullOrEmpty(returnsecureHash) && returnsecureHash == securehash)
                {
                    if (txnResponseCode != "0")
                    {
                        PaymentStatus = "invalid";
                    }
                    else
                    {
                        PaymentStatus = "approved";
                    }
                }

                ViewBag.PaymentStatus = PaymentStatus;

                var vpcResponse = new PaymentResponse(Request);
                return View(vpcResponse);
            }
            catch (Exception ex)
            {
                var message = "Exception encountered. " + ex.Message;
                return View("Error", ex);
            }
        }

        public ActionResult QueryDR([Bind(Include = "vpc_MerchTxnRef, vpc_User, vpc_Password")] string vpc_MerchTxnRef, string vpc_User, string vpc_Password)
        {
            ViewBag.QueryDRStatus = "none";

            if (string.IsNullOrEmpty(vpc_MerchTxnRef) || string.IsNullOrEmpty(vpc_User) || string.IsNullOrEmpty(vpc_Password))
                return View(new QueryDRResponse());

            var VPC_URL = "https://migs.mastercard.com.au/vpcdps";
            var paymentRequest = new PaymentRequest
            {
                AccessCode = ConfigurationManager.AppSettings["MigsAccessCode"],
                MerchTxnRef = vpc_MerchTxnRef,
                User = vpc_User,
                Password = vpc_Password
            };

            var transactionData = paymentRequest.GetQueryDRParameters().OrderBy(t => t.Key, new VPCStringComparer()).ToList();

            var redirectUrl = VPC_URL + "?" + string.Join("&", transactionData.Select(item => HttpUtility.UrlEncode(item.Key) + "=" + HttpUtility.UrlEncode(item.Value)));

            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create(redirectUrl);
            req.Method = "POST";

            var response = (HttpWebResponse)req.GetResponse();

            var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();

            var queryString = responseString.Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);

            ViewBag.QueryDRStatus = "";

            QueryDRResponse model = new QueryDRResponse();
            model.message = queryString["vpc_Message"];
            model.DRExists = queryString["vpc_DRExists"];
            model.TxnResponseCode = queryString["vpc_TxnResponseCode"];
            return View(model);
        }

        // POST: Payment/InitiatePayment
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult InitiatePayment([Bind(Include = "vpc_Amount, vpc_MerchTxnRef, vpc_OrderInfo, vpc_ReturnURL")] string vpc_Amount, string vpc_MerchTxnRef, string vpc_OrderInfo, string vpc_ReturnURL)
        {
            try
            {
                //region parameters
                var VPC_URL = "https://migs.mastercard.com.au/vpcpay";
                var paymentRequest = new PaymentRequest
                {
                    Amount = vpc_Amount,
                    MerchTxnRef = vpc_MerchTxnRef,
                    OrderInfo = vpc_OrderInfo,
                    ReturnUrl = vpc_ReturnURL
                };

                var transactionData = paymentRequest.GetParameters().OrderBy(t => t.Key, new VPCStringComparer()).ToList();

                var redirectUrl = VPC_URL + "?" + string.Join("&", transactionData.Select(item => HttpUtility.UrlEncode(item.Key) + "=" + HttpUtility.UrlEncode(item.Value)));

                transactionData = transactionData.Where(x => x.Key != "vpc_SecureHashType").ToList();

                string shaKey = ConfigurationManager.AppSettings["MigsSecureHashSecret"];
                string shaData = string.Join("&", transactionData.Select(item => item.Key + "=" + item.Value));

                redirectUrl += "&vpc_SecureHash=" + HttpUtility.UrlEncode(PaymentHelperMethods.CreateSHA256Signature(shaKey, shaData));

                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                var message = "Exception encountered. " + ex.Message;
                return View("Error", ex);
            }
        }
    }
}