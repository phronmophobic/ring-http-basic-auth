(ns ring.middleware.http-basic-auth
  "Ring middleware for basic HTTP authentication."
  (:use [remvee.base64 :as base64]))


(defn- get-credentials [req]
  (let [auth ((req :headers) "authorization")
        cred (and auth (base64/decode-str (last (re-find #"^Basic (.*)$" auth))))
        username (and cred (last (re-find #"^(.*):" cred)))
        password (and cred (last (re-find #":(.*)$" cred)))]
    [username password]))

(let [out *out*]
  (defn p [& args]
    (binding [*out* out]
      (apply println args))))

(defn wrap-with-credentials [app]
  (fn [req]
    (let [[username password] (get-credentials req)]
      (app (-> req
               (assoc-in [:auth :username] username)
               (assoc-in [:auth :password] password))))))

(defn wrap-with-authenticated? [app authenticated?]
  (fn [req]
    (let [{{:keys [username password]} :auth} req]
      (app (assoc-in req [:auth :authenticated?] (boolean (authenticated? req username password)))))))

(defn wrap-with-auth-headers [app & [realm denied-response]]
  (fn [req]
    (if (get-in req [:auth :authenticated?])
      (app req)
      (assoc
          (merge {:headers {"Content-Type" "text/plain"}
                  :body "HTTP authentication required."}
                 denied-response)
        :status  401
        :headers (merge (:headers denied-response)
                        {"WWW-Authenticate" (format
                                             "Basic realm=\"%s\"" (or realm "Restricted Area"))})))))

(defn wrap-auth [handler authenticated? & [realm denied-response]]
  (-> handler
      (wrap-with-auth-headers realm denied-response)
      (wrap-with-authenticated? authenticated?)
      (wrap-with-credentials)))

