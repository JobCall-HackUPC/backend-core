package main

import (
	"cloud.google.com/go/firestore"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	projectId = "jobcall-d64f4"
	defaultPort = "80"
	credsPath = "key.json"
	stackClientId= "20251"
	stackRedirectUri = "http://jofre/stacksignup" // Also update address in https://stackapps.com/apps/oauth/view/20251
	stackKey = "F2vW0rJ4Dz7I9LDwWfpN2A(("
	githubClientId = "1fb033ea6e2ea40d8c6f"
	githubRedirectUri = "http://jofre/githubsignup" // Also update address in https://github.com/settings/applications/1624162
)

var (
	client *firestore.Client
	ctx context.Context
	stackSecret string
	githubSecret string
)

type WebRTC struct {
	Type string `firestore:"type"`
	Sdp string `firestore:"sdp"`
}

type Call struct {
	Offer WebRTC `firestore:"offer"`
	Answer WebRTC `firestore:"answer"`
}

type StackAuthResponse struct{
	Error string `json:"error_message,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

type GithubAuthResponse struct{
	AccessToken string `json:"access_token,omitempty"`
	Scope string `json:"scope,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

type StackUseridResponse struct {
	Items []struct {
		AccountId  json.Number `json:"account_id"`
		Reputation json.Number `json:"reputation"`
		UserId     json.Number `json:"user_id"`
	} `json:"items"`
}

type GithubUserResponse struct {
	Login                   string    `json:"login"`
	Id                      int       `json:"id"`
	NodeId                  string    `json:"node_id"`
	AvatarUrl               string    `json:"avatar_url"`
	GravatarId              string    `json:"gravatar_id"`
	Url                     string    `json:"url"`
	HtmlUrl                 string    `json:"html_url"`
	FollowersUrl            string    `json:"followers_url"`
	FollowingUrl            string    `json:"following_url"`
	GistsUrl                string    `json:"gists_url"`
	StarredUrl              string    `json:"starred_url"`
	SubscriptionsUrl        string    `json:"subscriptions_url"`
	OrganizationsUrl        string    `json:"organizations_url"`
	ReposUrl                string    `json:"repos_url"`
	EventsUrl               string    `json:"events_url"`
	ReceivedEventsUrl       string    `json:"received_events_url"`
	Type                    string    `json:"type"`
	SiteAdmin               bool      `json:"site_admin"`
	Name                    string    `json:"name"`
	Company                 string    `json:"company"`
	Blog                    string    `json:"blog"`
	Location                string    `json:"location"`
	Email                   string    `json:"email"`
	Hireable                bool      `json:"hireable"`
	Bio                     string    `json:"bio"`
	TwitterUsername         string    `json:"twitter_username"`
	PublicRepos             int       `json:"public_repos"`
	PublicGists             int       `json:"public_gists"`
	Followers               int       `json:"followers"`
	Following               int       `json:"following"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	PrivateGists            int       `json:"private_gists"`
	TotalPrivateRepos       int       `json:"total_private_repos"`
	OwnedPrivateRepos       int       `json:"owned_private_repos"`
	DiskUsage               int       `json:"disk_usage"`
	Collaborators           int       `json:"collaborators"`
	TwoFactorAuthentication bool      `json:"two_factor_authentication"`
	Plan                    struct {
		Name          string `json:"name"`
		Space         int    `json:"space"`
		PrivateRepos  int    `json:"private_repos"`
		Collaborators int    `json:"collaborators"`
	} `json:"plan"`
}

type StackTopTags struct {
	Items []struct {
		UserId        int    `json:"user_id"`
		AnswerCount   int    `json:"answer_count"`
		AnswerScore   int    `json:"answer_score"`
		QuestionCount int    `json:"question_count"`
		QuestionScore int    `json:"question_score"`
		TagName       string `json:"tag_name"`
	} `json:"items"`
	HasMore        bool `json:"has_more"`
	QuotaMax       int  `json:"quota_max"`
	QuotaRemaining int  `json:"quota_remaining"`
}

type Site struct {
	UserId string   `firestore:"userid" json:"userid"`
	Token string    `firestore:"token" json:"-"`//json:"token"` // do not return the token on json responses
	Tags []UserTags `firestore:"tags" json:"tags"`
}

type UserTags struct{
	TagName       string `firestore:"tag_name" json:"tag_name"`
	Score 		  int `firestore:"score" json:"score"`
}

type TotalTags struct{
	TagName string `firestore:"tag_name"`
	TotalScore int `firestore:"total_score"`
	Users map[string]int `firestore:"users"`
}

type User struct {
	Id string `firestore:"id" json:"id"`
	Tmp string `firestore:"tmp" json:"-"` // for code verification of oauth, ignored when parsed as json
	Github Site `firestore:"github" json:"github"`
	Stack Site `firestore:"stack" json:"stack"`
	CallId string `firestore:"call_id" json:"call_id"`
}

func main() {
	stackRedirect, err := url.Parse(stackRedirectUri)
	if err != nil {
		log.Fatal(err)
	}
	githubRedirect, err := url.Parse(githubRedirectUri)
	if err != nil {
		log.Fatal(err)
	}

	stackSecret = os.Getenv("STACKSECRET")
	githubSecret = os.Getenv("GITHUBSECRET")

	// Create firebase client
	ctx = context.Background()
	client, err = firestore.NewClient(ctx, projectId, option.WithCredentialsFile(credsPath))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	http.HandleFunc("/stack", getStackURL)
	http.HandleFunc("/github", getGithubURL)
	http.HandleFunc(stackRedirect.Path, stackSignup)
	http.HandleFunc(githubRedirect.Path, githubSignup)
	http.HandleFunc("/stacklogout", stackLogout)
	http.HandleFunc("/githublogout", githubLogout)
	http.HandleFunc("/me", user)
	
	http.HandleFunc("/tags", getTags)
	http.HandleFunc("/call", call)
	
	http.HandleFunc("/test/", test)
	http.HandleFunc("/", genericHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func call(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	userId := "personadelmonton@gmail.com" // for debugging purposes
	client.Collection("user").Doc(string(userId)).Update(ctx, []firestore.Update{{Path: "call_id", Value: "15735a45-5024-410c-88ef-18f232953347"}})
}

func getTags(w http.ResponseWriter, request *http.Request) {
	docIter := client.Collection("tags").OrderBy("total_score", firestore.Desc).Limit(25).Documents(ctx)

	tagList := make(map[string]int)
	var tag TotalTags
	for {
		doc, err := docIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := doc.DataTo(&tag); err != nil{
			log.Fatal(err)
		}
		tagList[tag.TagName] = tag.TotalScore
	}
	j, err := json.Marshal(tagList)
	if err != nil{
		log.Fatal(err)
	}
	w.Header().Add("access-control-allow-origin", "*")
	fmt.Fprintf(w, "%v", string(j))
}



func user(w http.ResponseWriter, r *http.Request) {
	userId := r.Header.Get("mail")
	if userId == ""{
		userId = "a" //for testing purposes
		//w.WriteHeader(404)
		//return
	}

	collection := client.Collection("user")
	user := collection.Doc(userId)
	_, _ = user.Create(ctx, User{Id: userId})
	doc, err := collection.Doc(string(userId)).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var userInfo User
	err = doc.DataTo(&userInfo)
	if err != nil{
		log.Fatal(err)
	}
	j, err := json.Marshal(userInfo)
	if err != nil{
		log.Fatal(err)
	}
	fmt.Fprintf(w, "%v", string(j))
	go getUserStackTags(userInfo.Id)
}

func githubLogout(w http.ResponseWriter, r *http.Request) {
	// Loading from firestore
	userId := r.Header.Get("mail")
	if userId == ""{
		userId = "a" //for testing purposes
		//w.WriteHeader(404)
		//return
	}
	collection := client.Collection("user")
	doc, err := collection.Doc(string(userId)).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var user User
	err = doc.DataTo(&user)
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("https://api.github.com/applications/%v/token", githubClientId), strings.NewReader(fmt.Sprintf("{\"access_token\":\"%v\"}", user.Github.Token)))
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(githubClientId, githubSecret)
	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Remove token from DB
	collection.Doc(string(userId)).Update(ctx, []firestore.Update{{Path: "github.token", Value: ""}, {Path: "github.userid", Value:""}})
}

func stackLogout(w http.ResponseWriter, r *http.Request) {
	// Loading from firestore
	userId := r.Header.Get("mail")
	if userId == ""{
		userId = "a" //for testing purposes
		//w.WriteHeader(404)
		//return
	}
	collection := client.Collection("user")
	doc, err := collection.Doc(string(userId)).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var user User
	err = doc.DataTo(&user)
	if err != nil {
		log.Fatal(err)
	}
	_, err = http.Get(fmt.Sprintf("https://api.stackexchange.com/2.2/apps/%v/de-authenticate?key=%v", user.Stack.Token, stackKey))
	if err != nil {
		log.Fatal(err)
	}

	// Remove token from DB
	collection.Doc(string(userId)).Update(ctx, []firestore.Update{{Path: "stack.token", Value: ""}, {Path: "stack.userid", Value: ""}})
}




func getStackURL (w http.ResponseWriter, r *http.Request){
	state := uuid.New().String()
	userId := r.Header.Get("mail")
	if userId == ""{
		userId = "a" //for testing purposes
		//w.WriteHeader(404)
		//return
	}

	collection := client.Collection("user")
	user := collection.Doc(userId)
	_, err := user.Create(ctx, User{Id: userId, Tmp: state})
	if err != nil{
		// Let's assume an error will only trigger when the user already exists
		user := collection.Doc(string(userId))
		user.Update(ctx, []firestore.Update{{Path: "tmp", Value: state}})
	}

	fmt.Fprintf(w, "https://stackoverflow.com/oauth?client_id=%v&scope=no_expiry&redirect_uri=%v&state=%v", stackClientId, url.PathEscape(stackRedirectUri), state)
}


func getGithubURL(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	userId := r.Header.Get("mail")
	if userId == ""{
		userId = "a" //for testing purposes
		//w.WriteHeader(404)
		//return
	}

	collection := client.Collection("user")
	user := collection.Doc(userId)
	_, err := user.Create(ctx, User{Id: userId, Tmp: state})
	if err != nil{
		// Let's assume an error will only trigger when the user already exists
		user := collection.Doc(string(userId))
		user.Update(ctx, []firestore.Update{{Path: "tmp", Value: state}})
	}

	fmt.Fprintf(w, "https://github.com/login/oauth/authorize?client_id=%v&scope=repo:status&redirect_uri=%v&state=%v", githubClientId, url.PathEscape(githubRedirectUri), state)
}

func stackSignup(w http.ResponseWriter, r *http.Request){
	state := r.FormValue("state")

	collection := client.Collection("user")
	docIter := collection.Where("tmp", "==", state).Documents(ctx)
	var user User
	for {
		doc, err := docIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := doc.DataTo(&user); err != nil{
			w.WriteHeader(403)
			return
		}
	}
	resp, err := http.PostForm("https://stackoverflow.com/oauth/access_token/json", url.Values{"client_id": {stackClientId}, "client_secret" : {stackSecret}, "code": {r.FormValue("code")}, "redirect_uri": {url.PathEscape(stackRedirectUri)}, "state": {state}})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var token StackAuthResponse
	if err := json.Unmarshal(body, &token); err != nil{
		log.Fatal(err)
	}

	if token.Error != ""{
		log.Fatal(token.Error)
	}

	// Saving into firestore
	userUpdate := collection.Doc(user.Id)
	userUpdate.Update(ctx, []firestore.Update{{Path: "stack.token", Value: token.AccessToken}, {Path: "tmp", Value: ""}})
	getStackId(user.Id)
	}

func githubSignup (w http.ResponseWriter, r *http.Request){
	state := r.FormValue("state")

	collection := client.Collection("user")
	docIter := collection.Where("tmp", "==", state).Documents(ctx)
	var user User
	for {
		doc, err := docIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := doc.DataTo(&user); err != nil{
			w.WriteHeader(403)
			return
		}
	}

	req, err := http.NewRequest(http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(url.Values{"client_id": {githubClientId}, "client_secret" : {githubSecret}, "code": {r.FormValue("code")}, "redirect_uri": {githubRedirectUri}, "state": {state}}.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var token GithubAuthResponse
	if err = json.Unmarshal(body, &token); err != nil{
		log.Fatal(err)
	}

	// Saving into firestore
	userUpdate := collection.Doc(user.Id)
	userUpdate.Update(ctx, []firestore.Update{{Path: "github.token", Value: token.AccessToken}, {Path: "tmp", Value: ""}})
	getGithubId(user.Id)
}


func getStackId(userId string){
	filter := "!LnMTyEndI7V2SIJX2yEmMj"
	doc, err := client.Collection("user").Doc(userId).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var userInfo User
	err = doc.DataTo(&userInfo)
	if err != nil{
		log.Fatal(err)
	}
	url := fmt.Sprintf("https://api.stackexchange.com/2.2/me?key=%v&site=stackoverflow&order=desc&sort=reputation&access_token=%v&filter=%v", stackKey, userInfo.Stack.Token, filter)
	resp, err := http.Get(url)
	if err != nil{
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var userid StackUseridResponse
	if err = json.Unmarshal(body, &userid); err != nil{
		log.Fatal(err)
	}
	client.Collection("user").Doc(userId).Update(ctx, []firestore.Update{{Path: "stack.userid", Value: string(userid.Items[0].UserId)}})
}


func getGithubId(userId string){
	doc, err := client.Collection("user").Doc(userId).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var userInfo User
	err = doc.DataTo(&userInfo)
	if err != nil{
		log.Fatal(err)
	}
	url := fmt.Sprintf("https://api.github.com/user")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("authorization", fmt.Sprintf("token %v", userInfo.Github.Token))

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var userid GithubUserResponse
	if err = json.Unmarshal(body, &userid); err != nil{
		log.Fatal(err)
	}
	client.Collection("user").Doc(userId).Update(ctx, []firestore.Update{{Path: "github.userid", Value: string(userid.Login)}})
}

func getUserStackTags(userId string) {
	//filter := "!LnMTyEndI7V2SIJX2yEmMj"
	doc, err := client.Collection("user").Doc(userId).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var userInfo User
	err = doc.DataTo(&userInfo)
	if err != nil{
		log.Fatal(err)
	}
	url := fmt.Sprintf("https://api.stackexchange.com/2.2/me/top-tags?key=%v&pagesize=100&site=stackoverflow&order=desc&sort=reputation&access_token=%v", stackKey, userInfo.Stack.Token)
	resp, err := http.Get(url)
	if err != nil{
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var stackTags StackTopTags
	if err = json.Unmarshal(body, &stackTags); err != nil{
		log.Fatal(err)
	}

	var tags []UserTags
	for _,item := range stackTags.Items {
		tags = append(tags, UserTags{TagName: item.TagName, Score: item.AnswerScore+item.QuestionScore})
	}

	// Adding tags to user
	client.Collection("user").Doc(userId).Update(ctx, []firestore.Update{{Path: "stack.tags", Value: tags}})

	// Adding tags to totals
	for _,tag := range tags {
		fTag := client.Collection("tags").Doc(tag.TagName)
		_, err := fTag.Create(ctx, TotalTags{TagName: tag.TagName, TotalScore: tag.Score, Users: map[string]int{userId: tag.Score}})
		if err != nil{
			// Let's assume an error will only trigger when the tag already exists
			oldTagResponse, err := client.Collection("tags").Doc(tag.TagName).Get(ctx)
			if err != nil{
				log.Fatal(err)
			}
			var oldTag TotalTags
			if err = oldTagResponse.DataTo(&oldTag); err != nil{
				log.Fatal(err)
			}
			var newScore int
			if _, ok := oldTag.Users[userId]; !ok {
				newScore = oldTag.TotalScore+tag.Score
				client.Collection("tags").Doc(tag.TagName).Update(ctx, []firestore.Update{{Path: "total_score", Value: newScore}, {Path:"users", Value:  map[string]int{userId: tag.Score} }})
			}
		}
	}
}





/*---------------------------------------------------------------*/
func genericHandler(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Path) <= 1{
		w.WriteHeader(200)
		return
	}
	path := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")[2:]
	//log.Printf("%+v\n", path)
	var collection *firestore.CollectionRef
	switch len(path) {
	case 3:
		collection = client.Collection(path[0])
		docsnap, err := collection.Doc(path[1]).Get(ctx)
		if err != nil {
			log.Fatal(err)
		}
		var call Call
		err = docsnap.DataTo(&call)
		if err != nil{
			log.Fatal(err)
		}
		switch strings.ToLower(path[2]) {
		case "answer":
			log.Print(path[2])
			log.Printf("%+v", call)
			log.Printf("%+v", call.Answer)
			fmt.Fprintf(w, "%v\n", call.Answer.Sdp)
		case "offer":
			log.Print(path[2])
			fmt.Fprintf(w, "%v\n", call.Offer.Sdp)
		default:
			w.WriteHeader(404)
		}
	case 2:
		collection = client.Collection(path[0])
		docs, err := collection.Doc(path[1]).Get(ctx)
		if err != nil {
			log.Fatal(err)
		}
		var call Call
		err = docs.DataTo(&call)
		if err != nil{
			log.Fatal(err)
		}
		fmt.Fprintf(w, "%+v\n", call)
	case 1:
		collection = client.Collection(path[0])
		docs, err := collection.Documents(ctx).GetAll()
		if err != nil {
			log.Fatal(err)
		}
		var call Call
		for _, doc := range docs {
			err = doc.DataTo(&call)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintf(w, "%+v\n", call)
		}
	default:
		w.WriteHeader(404)
	}
}

func test (w http.ResponseWriter, r *http.Request){
	collection := client.Collection("user")
	user := collection.Doc("1")
	wr, err := user.Create(ctx, User{Id:"1"})
	if err != nil{
		log.Fatal(err)
	}
	fmt.Fprintf(w, "%+v\n", wr)
}