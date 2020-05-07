(ns pbc-playground.meetup
  (:require ;[clojure.test :refer [deftest is]]
            [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys :as buddy-keys]
            [buddy.core.dsa :as dsa])
  (:import (java.time OffsetDateTime)))

;Note!
;Generate keys by running:
;./generate-key-pair nordea
;./generate-key-pair op
;./generate-key-pair lehman

;Immutable Tamper-proof Distributed database
;It is a permissioned network where known semi-trusted parties can make transactions between each other

(defn- read-private-key [key-name]
  (buddy-keys/private-key (str "keys/" key-name ".pem") "secret"))

(defn- read-public-key [key-name]
  (buddy-keys/public-key (str "keys/" key-name ".pem")))

(def signing-algorithm :rsassa-pss+sha256)

(def nodes
  {"OP" {:id "OP" :private-key (read-private-key "op-private") :public-key (read-public-key "op-public")}
   "Nordea" {:id "Nordea" :private-key (read-private-key "nordea-private") :public-key (read-public-key "nordea-public")}
   "Lehman Brothers" {:id "Lehman Brothers" :private-key (read-private-key "lehman-private") :public-key (read-public-key "lehman-public")}})
(def op-node (get nodes "OP"))
(def nordea-node (get nodes "Nordea"))
(def lehman-node (get nodes "Lehman Brothers"))

(defn- sign [data private-key]
  (-> (dsa/sign data {:key private-key :alg signing-algorithm})
      (codecs/bytes->hex)))

(defn- verify-sign [data signature public-key]
  (dsa/verify data (codecs/hex->bytes signature) {:key public-key :alg signing-algorithm}))


(defn- sha256 [s]
  (-> (buddy-hash/sha256 s)
      (codecs/bytes->hex)))

(defn- serialize [s] (pr-str s))

(defn generate-transaction [data previous-tx required-signers]
  (let [block {:timestamp (OffsetDateTime/now)
               :data data
               :validator "(fn [current-data previous-data] (= current-data (inc previous-data)))"
               :required-signers required-signers
               :preceeding-hash (:hash previous-tx)}]
    {:hash (sha256 (serialize block))
     :signatures {}
     :block block}))

(defn- validate-transaction-hash [tx]
  (= (:hash tx) (-> tx :block serialize sha256)))

(defn- validate-code [current-tx previous-tx]
  (let [validator-fn (-> current-tx :block :validator read-string eval)]
    (validator-fn (-> current-tx :block :data) (-> previous-tx :block :data))))

(defn- validate-chain [chain]
  (loop [txs chain]
    (let [[current-tx previous-tx] txs]
      (if (nil? previous-tx)
        true
        (if (and (validate-transaction-hash current-tx)
                 (validate-code current-tx previous-tx)
                 ;Verify signatures
                 (= (-> current-tx :block :preceeding-hash) (:hash previous-tx)))
          (recur (rest txs))
          false)))))

(defn sign-tx [tx {:keys [id private-key]}]
  (let [block (:block tx)
        signature (sign (serialize block) private-key)]
    (update tx :signatures assoc id signature)))

(let [nordea-chain (atom '())
      op-chain (atom '())
      spent-transaction-hashes (atom '())
      genesis (generate-transaction 1 nil ["Nordea" "OP"])
      tx (generate-transaction 2 genesis ["Nordea" "OP"])
      _ (swap! nordea-chain genesis)
      _ (swap! nordea-chain tx)
      cheat-tx (generate-transaction 2 genesis ["Lehman Brothers"])
      ]
  (validate-chain @nordea-chain))
  ;(sign-tx tx nordea-node))



























































;Storage of good code


