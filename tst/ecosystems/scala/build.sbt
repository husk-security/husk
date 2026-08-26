ThisBuild / scalaVersion := "2.13.12"
ThisBuild / organization := "com.example"

name := "husk-scala-fixture"

// Core dependencies (cross-built and plain Maven coordinates)
libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0"
libraryDependencies += "com.google.guava" % "guava" % "33.0.0-jre"

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.2.18" % Test,
  "ch.qos.logback" % "logback-classic" % "1.5.6"
)
