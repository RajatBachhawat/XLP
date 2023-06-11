package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"bufio"

	kafka "github.com/segmentio/kafka-go"
)

func producerHandler(kafkaWriter *kafka.Writer, w *bufio.Writer) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Fatalln(err)
		}
		msg := kafka.Message{
			Key:   []byte(fmt.Sprintf("address-%s", req.RemoteAddr)),
			Value: body,
		}
		err = kafkaWriter.WriteMessages(req.Context(), msg)
		
		if err == nil {
			fmt.Fprintf(w,"produced message at topic:%v partition:%v offset:%v	%s = %s\n", msg.Topic, msg.Partition, msg.Offset, string(msg.Key), string(msg.Value))
		}

		if err != nil {
			wrt.Write([]byte(err.Error()))
			log.Fatalln(err)
		}
	})
}

func getKafkaWriter(kafkaURL, topic string) *kafka.Writer {
	return &kafka.Writer{
		Addr:     kafka.TCP(kafkaURL),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
}

func main() {
	// get kafka writer using environment variables.
	kafkaURL := os.Getenv("kafkaURL")
	topic := os.Getenv("topic")
	kafkaWriter := getKafkaWriter(kafkaURL, topic)

	defer kafkaWriter.Close()

	f, err := os.OpenFile("/app/log/out.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	// Add handle func for producer.
	http.HandleFunc("/", producerHandler(kafkaWriter, w))

	// Run the web server.
	fmt.Fprintf(w,"start producer-api ... !!\n")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
