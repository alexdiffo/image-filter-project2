import express from 'express';
import { Application, Request, Response, NextFunction, Errback } from "express";
import bodyParser from 'body-parser';
import { filterImageFromURL, deleteLocalFiles } from './util/util';
import { Auth } from './auth';
import { requireAuth } from './auth';


(async () => {

  // Init the Express application
  const app = express();

  // Set the network port
  const port = process.env.PORT || 8082;

  // Use the body parser middleware for post requests
  app.use(bodyParser.json());

  app.use('/auth', Auth)

  // @TODO1 IMPLEMENT A RESTFUL ENDPOINT
  // GET /filteredimage?image_url={{URL}}
  // endpoint to filter an image from a public url.
  // IT SHOULD
  //    1
  //    1. validate the image_url query
  //    2. call filterImageFromURL(image_url) to filter the image
  //    3. send the resulting file in the response
  //    4. deletes any files on the server on finish of the response
  // QUERY PARAMATERS
  //    image_url: URL of a publicly accessible image
  // RETURNS
  //   the filtered image file [!!TIP res.sendFile(filteredpath); might be useful]

  /**************************************************************************** */

  app.get("/filteredimage", requireAuth, async (req: Request, res: Response, next: NextFunction) => {

    try {
      let filteredpath: string = await filterImageFromURL(req.query.image_url) as string;
      if (!filteredpath) {
        return res.status(400)
          .send(`image not found`);
      }

      return res.status(200)
        .sendFile(filteredpath, () => {
          deleteLocalFiles([filteredpath]);
        });

    } catch (e) {
      return next(e);
    }

  });





  //! END @TODO1

  // Root Endpoint
  // Displays a simple message to the user
  app.get("/", async (req: Request, res: Response) => {
    res.send("Welcome to Alex image filter App. try GET /filteredimage?image_url={{}} . Don't forget to start by requiring authorization token through the url : http://image-filter-alex-dev-dev.us-east-1.elasticbeanstalk.com/auth ")
  });


  // Start the Server
  app.listen(port, () => {
    console.log(`server running http://localhost:${port}`);
    console.log(`press CTRL+C to stop server`);
  });
})();