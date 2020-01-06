package main

import "fmt"

func factorial(n int , next func(int)){
	if n== 0 {
		next(1)
	}else {
		factorial(n-1, func(k int){
			next(n*k)

		})
	}
}

func main(){
	factorial(2, func (result int){
		fmt.Println(result)
	})
}