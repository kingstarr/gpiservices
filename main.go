package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"io/ioutil"
	"net/http"
	"strconv"
	"log"
	"time"
	_ "github.com/go-sql-driver/mysql"
        "database/sql"
	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
)
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}
type Exception struct {
	Message string `json:"message"`
}
type jsonErr struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},
	Route{
		"gpiservice",
		"GET",
		"/gpiservice/{serviceid}",
		GPIService,
	},
	Route{
		"allgpiservices",
		"GET",
		"/allgpiservices",
		AllGPIServices,
	},
	Route{
		"gpitest",
		"GET",
		"/gpitest/{testid}",
		GPITest,
	},
	Route{
		"allgpitests",
		"GET",
		"/allgpitests",
		AllGPITests,
	},
	Route{
		"TodoCreate",
		"POST",
		"/jkl",
		TodoCreate,
	},
	Route{
		"TodoShow",
		"GET",
		"/pop/{todoId}",
		TodoShow,
	},Route{
		"TestEndpoint",
		"GET",
		"/testendpoint",
		ValidateMiddleware(TestEndpoint),
	},Route{
		"ProtectedEndpoint",
		"GET",
		"/protected",
		ProtectedEndpoint,
	},Route{
		"CreateTokenEndpoint",
		"POST",
		"/authenticate",
		CreateTokenEndpoint,
	},
}

type Todo struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	Status bool      `json:"status"`
	SDate       time.Time `json:"sdate"`
}

type Todos []Todo

var currentId int

var todos Todos

type sAllGPIServices struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Status int      `json:"status"`
	SDate      string `json:"sdate"`
}

//type Stags []sAllGPIServices

//var tags Stags

func main() {
	router := NewRouter()

	log.Fatal(http.ListenAndServe(":8080", router))


}

func NewRouter() *mux.Router {

	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler http.Handler

		handler = route.HandlerFunc
		handler = Logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)

	}

	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", "ssd:ssd@/gpiservice?charset=utf8")
    checkErr(err)
    defer db.Close()

    err = db.Ping()
    if err != nil {
    	log.Print(err.Error())
        //db.Close()
        fmt.Fprint(w, "Welcome! This is the Main GPI WebServer but your database is not connected\n")
        fmt.Fprint(w, "Please note that this server is only available as an API Services Provider until it is enhanced with GUI\n")
        fmt.Fprint(w, "Kindly write a mail to kingsley.ifedayo@my-gpi.com if you need to get the documentation for the API Interface\n")
    } else {
    	fmt.Fprint(w, "Welcome! This is the Main GPI WebServer\n")
    }
	//fmt.Fprint(w, "Welcome! This is the Main GPI WebServer\n")

}

func AllGPITests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(todos); err != nil {
		panic(err)
	}
}

func GPITest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var todoId int
	var err error
	if todoId, err = strconv.Atoi(vars["testid"]); err != nil {
		panic(err)
	}
	todo := RepoFindTodo(todoId)
	if todo.Id > 0 {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(todo); err != nil {
			panic(err)
		}
		return
	}

	// If we didn't find it, 404
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: "Not Found"}); err != nil {
		panic(err)
	}

}

func AllGPIServices(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("go")
	//var tags Stags
	r.ParseForm()
  
	param1 := r.Form.Get("pallw")

	stag := []*sAllGPIServices{}

	if (param1=="allowed") {
			db, err := sql.Open("mysql", "ssd:ssd@/gpiservice?charset=utf8")
    checkErr(err)
    defer db.Close()


    results, err := db.Query("SELECT id, name, status, sdate FROM allservices")
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	
	

	for results.Next() {
		var tag sAllGPIServices
		// for each row, scan the result into our tag composite object
		err = results.Scan(&tag.ID, &tag.Name, &tag.Status, &tag.SDate)
		if err != nil {
			panic(err.Error()) // proper error handling required
		}
		ttag :=new(sAllGPIServices)
		ttag.ID=tag.ID
		ttag.Name=tag.Name+param1
		ttag.Status=tag.Status
		ttag.SDate=tag.SDate
		stag=append(stag,ttag)

                // and then print out the tag's Name attribute
		log.Printf(tag.Name)

	}
		}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	//w.Header().Set("Host", "*")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(stag); err != nil {
		panic(err)
	}
}

func TodoShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var todoId int
	var err error
	if todoId, err = strconv.Atoi(vars["todoId"]); err != nil {
		panic(err)
	}
	todo := RepoFindTodo(todoId)
	if todo.Id > 0 {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(todo); err != nil {
			panic(err)
		}
		return
	}

	// If we didn't find it, 404
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: "Not Found"}); err != nil {
		panic(err)
	}

}

func GPIService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var todoId int
	var err error
	if todoId, err = strconv.Atoi(vars["serviceid"]); err != nil {
		panic(err)
	}
	todo := RepoFindTodo(todoId)
	if todo.Id > 0 {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(todo); err != nil {
			panic(err)
		}
		return
	}

	// If we didn't find it, 404
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: "Not Found"}); err != nil {
		panic(err)
	}

}
/*
Test with this curl command:

curl -H "Content-Type: application/json" -d '{"name":"New Todo"}' http://localhost:8080/todos

*/
func TodoCreate(w http.ResponseWriter, r *http.Request) {
	var todo Todo
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		panic(err)
	}
	if err := r.Body.Close(); err != nil {
		panic(err)
	}
	if err := json.Unmarshal(body, &todo); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			panic(err)
		}
	}

	t := RepoCreateTodo(todo)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(t); err != nil {
		panic(err)
	}
}

func init() {
	RepoCreateTodo(Todo{Name: "Testing Engine"})
	RepoCreateTodo(Todo{Name: "Employee Management"})
	RepoCreateTodo(Todo{Name: "Employee Attendance"})
	RepoCreateTodo(Todo{Name: "mEmplhjgfdoyee Attendnmkiuygtancem"})
}

func RepoFindTodo(id int) Todo {
	for _, t := range todos {
		if t.Id == id {
			return t
		}
	}
	// return empty Todo if not found
	return Todo{}
}

//this is bad, I don't think it passes race condtions
func RepoCreateTodo(t Todo) Todo {
	currentId += 1
	t.Id = currentId
	todos = append(todos, t)
	return t
}

func RepoDestroyTodo(id int) error {
	for i, t := range todos {
		if t.Id == id {
			todos = append(todos[:i], todos[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("Could not find record with id of %d to delete", id)
}

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Printf(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}

func checkErr(err error) {
        if err != nil {
            panic(err)
        }
    }

    func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					context.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
	})
	tokenString, error := token.SignedString([]byte("secret"))
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("secret"), nil
	})
	//header('Content-type: application/json');
 //header('Access-Control-Allow-Origin: *');
 w.Header().Set("Access-Control-Allow-Origin", "*")
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080/testendpoint/")
	json.NewEncoder(w).Encode(user)
}